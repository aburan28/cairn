//! Installing the agent under systemd: a unit, an environment file, a
//! system user, and the three `systemctl` calls.
//!
//! `docs/install.md` says no package installs a service, and that stays
//! true: a `.deb` or `.rpm` runs nothing as root and leaves no unit behind.
//! This is the *explicit* route -- an operator who runs `cairn agent install`
//! is asking for exactly a service, and gets one they can read first with
//! `--print`. The unit text is compiled into the binary from
//! `cairn-agent.service` beside this file, so what `--print` shows is what
//! is written.
//!
//! # The user
//!
//! By default a system user `cairn-agent` with no login, in the `docker`
//! (or `podman`) and `kvm` groups where those exist. Rootless gVisor works
//! for root filesystem jobs; image jobs go through the engine, which runs
//! them as the engine's daemon does. `--user root` is honoured and said
//! back, because a box whose only sandbox is `runsc` with cgroup limits
//! needs it -- that is a trade the operator makes knowingly, not a default.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::AgentError;

const UNIT: &str = include_str!("cairn-agent.service");

pub const UNIT_NAME: &str = "cairn-agent.service";
pub const UNIT_PATH: &str = "/etc/systemd/system/cairn-agent.service";
pub const ENV_FILE: &str = "/etc/cairn-agent/agent.env";
pub const DEFAULT_USER: &str = "cairn-agent";

/// Everything the installer writes down.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Install {
    /// Absolute path of this binary, as `ExecStart` will name it.
    pub exec: PathBuf,
    pub user: String,
    pub data_dir: PathBuf,
    /// `KEY=VALUE` lines for the environment file.
    pub env: Vec<(String, String)>,
    /// Supplementary groups that exist on this host.
    pub groups: Vec<String>,
}

impl Install {
    /// The unit text, with every placeholder filled.
    pub fn unit(&self) -> String {
        let root = self.user == "root";
        UNIT.replace("{{USER}}", &self.user)
            .replace("{{GROUP}}", if root { "root" } else { &self.user })
            .replace("{{GROUPS}}", &self.groups.join(" "))
            .replace("{{ENV_FILE}}", ENV_FILE)
            .replace("{{EXEC}}", &self.exec.display().to_string())
            .replace("{{DATA}}", &self.data_dir.display().to_string())
            // Root keeps the ability to gain capabilities because a native
            // runsc with cgroups needs them; a system user never had any.
            .replace("{{NO_NEW_PRIVILEGES}}", if root { "false" } else { "true" })
    }

    /// The environment file: one variable per line, values quoted so a
    /// space in a URL list or a name survives systemd's parser.
    pub fn env_file(&self) -> String {
        let mut text = String::from(
            "# cairn-agent configuration, read by cairn-agent.service.\n\
             # Edit, then: systemctl restart cairn-agent\n",
        );
        for (key, value) in &self.env {
            text.push_str(&format!("{key}=\"{}\"\n", value.replace('"', "\\\"")));
        }
        text
    }
}

/// Groups worth adding the agent's user to, among those the host has.
pub fn supplementary_groups(group_file: &str) -> Vec<String> {
    ["docker", "podman", "kvm", "render", "video"]
        .iter()
        .filter(|wanted| {
            group_file
                .lines()
                .any(|line| line.split(':').next() == Some(wanted))
        })
        .map(|g| g.to_string())
        .collect()
}

fn run(program: &str, args: &[&str]) -> Result<(), AgentError> {
    let status = Command::new(program)
        .args(args)
        .status()
        .map_err(|e| AgentError::Unavailable(format!("{program}: {e}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(AgentError::Unavailable(format!(
            "{program} {} exited {}",
            args.join(" "),
            status.code().unwrap_or(-1)
        )))
    }
}

fn systemd_present() -> bool {
    Path::new("/run/systemd/system").is_dir()
}

/// Write the unit and environment file, make the user and data directory,
/// then enable and start. Needs root.
pub fn install(plan: &Install, start: bool) -> Result<Vec<String>, AgentError> {
    if !systemd_present() {
        return Err(AgentError::Unavailable(
            "this host is not running systemd (/run/systemd/system is absent); print the \
             unit with --print and adapt it to your service manager"
                .into(),
        ));
    }
    let mut done = Vec::new();
    if plan.user != "root" && !user_exists(&plan.user) {
        run(
            "useradd",
            &[
                "--system",
                "--no-create-home",
                "--shell",
                "/usr/sbin/nologin",
                "--home-dir",
                &plan.data_dir.display().to_string(),
                &plan.user,
            ],
        )?;
        done.push(format!("created system user {}", plan.user));
    }
    fs::create_dir_all(&plan.data_dir)?;
    for sub in ["jobs/queue", "jobs/running", "jobs/done", "runsc"] {
        fs::create_dir_all(plan.data_dir.join(sub))?;
    }
    if plan.user != "root" {
        run(
            "chown",
            &[
                "-R",
                &format!("{}:{}", plan.user, plan.user),
                &plan.data_dir.display().to_string(),
            ],
        )?;
    }
    done.push(format!("data directory {}", plan.data_dir.display()));
    if let Some(parent) = Path::new(ENV_FILE).parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(ENV_FILE, plan.env_file())?;
    // The environment file holds node addresses and a name: not secret, but
    // not everybody's business either.
    run("chmod", &["0640", ENV_FILE])?;
    done.push(format!("wrote {ENV_FILE}"));
    fs::write(UNIT_PATH, plan.unit())?;
    done.push(format!("wrote {UNIT_PATH}"));
    run("systemctl", &["daemon-reload"])?;
    if start {
        run("systemctl", &["enable", "--now", UNIT_NAME])?;
        done.push(format!("enabled and started {UNIT_NAME}"));
    } else {
        run("systemctl", &["enable", UNIT_NAME])?;
        done.push(format!("enabled {UNIT_NAME} (not started)"));
    }
    Ok(done)
}

/// Stop and disable the unit and remove what `install` wrote. The data
/// directory -- receipts, outputs -- stays unless `purge`.
pub fn uninstall(data_dir: &Path, purge: bool) -> Result<Vec<String>, AgentError> {
    let mut done = Vec::new();
    if systemd_present() && Path::new(UNIT_PATH).exists() {
        // Stop failures are not fatal: a unit that never started cannot be
        // stopped, and the file still has to go.
        let _ = Command::new("systemctl")
            .args(["disable", "--now", UNIT_NAME])
            .status();
        done.push(format!("disabled and stopped {UNIT_NAME}"));
    }
    for path in [UNIT_PATH, ENV_FILE] {
        if Path::new(path).exists() {
            fs::remove_file(path)?;
            done.push(format!("removed {path}"));
        }
    }
    if systemd_present() {
        let _ = Command::new("systemctl").arg("daemon-reload").status();
    }
    if purge && data_dir.exists() {
        fs::remove_dir_all(data_dir)?;
        done.push(format!("removed {}", data_dir.display()));
    } else if data_dir.exists() {
        done.push(format!(
            "kept {} (receipts and outputs); --purge removes it",
            data_dir.display()
        ));
    }
    Ok(done)
}

fn user_exists(name: &str) -> bool {
    fs::read_to_string("/etc/passwd")
        .map(|text| {
            text.lines()
                .any(|line| line.split(':').next() == Some(name))
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(user: &str) -> Install {
        Install {
            exec: PathBuf::from("/usr/bin/cairn"),
            user: user.to_string(),
            data_dir: PathBuf::from("/var/lib/cairn-agent"),
            env: vec![
                (
                    "CAIRN_AGENT_NODES".to_string(),
                    "http://10.0.0.2:8080,http://10.0.0.3:8080".to_string(),
                ),
                ("CAIRN_AGENT_NAME".to_string(), "gpu \"box\" 1".to_string()),
            ],
            groups: vec!["docker".to_string(), "kvm".to_string()],
        }
    }

    #[test]
    fn the_unit_is_filled_in_and_hardened_for_a_system_user() {
        let unit = plan("cairn-agent").unit();
        assert!(!unit.contains("{{"), "a placeholder survived:\n{unit}");
        assert!(unit.contains("User=cairn-agent\n"));
        assert!(unit.contains("Group=cairn-agent\n"));
        assert!(unit.contains("SupplementaryGroups=docker kvm\n"));
        assert!(unit.contains("ExecStart=/usr/bin/cairn agent run\n"));
        assert!(unit.contains("EnvironmentFile=-/etc/cairn-agent/agent.env\n"));
        assert!(unit.contains("NoNewPrivileges=true\n"));
        assert!(unit.contains("ReadWritePaths=/var/lib/cairn-agent\n"));
        assert!(unit.contains("WantedBy=multi-user.target"));

        let root = plan("root").unit();
        assert!(root.contains("User=root\nGroup=root\n"));
        assert!(root.contains("NoNewPrivileges=false\n"));
    }

    #[test]
    fn the_environment_file_quotes_values() {
        let env = plan("x").env_file();
        assert!(env.contains("CAIRN_AGENT_NODES=\"http://10.0.0.2:8080,http://10.0.0.3:8080\"\n"));
        assert!(env.contains("CAIRN_AGENT_NAME=\"gpu \\\"box\\\" 1\"\n"));
    }

    #[test]
    fn supplementary_groups_are_only_the_ones_the_host_has() {
        let groups = "root:x:0:\ndocker:x:999:alice\nvideo:x:44:\nstaff:x:50:\n";
        assert_eq!(supplementary_groups(groups), ["docker", "video"]);
        assert!(supplementary_groups("").is_empty());
    }
}
