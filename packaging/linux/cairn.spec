# Wraps a cairn binary that already exists; nothing is compiled here. See
# build-rpm.sh, which is what supplies every %{cairn_*} macro below, and
# build-deb.sh for why packaging consumes the tested binary instead of
# building another.

# Every one of these switches off something rpmbuild does to a binary by
# default, and each would break the one property this package is built to
# have: that /usr/bin/cairn is byte-for-byte the file release.yml tested.
#
#   debug_package        splits debug info out into a -debuginfo subpackage,
#                        rewriting the binary to do it.
#   __os_install_post    runs brp-strip and friends over the buildroot. A
#                        stripped binary is a different binary.
#   _build_id_links      defaults to `compat` on the runner, which adds
#                        /usr/lib/.build-id/xx/yyyy symlinks to the file list,
#                        so the package would own paths nobody chose.
%global debug_package %{nil}
%global __os_install_post %{nil}
%global _build_id_links none

# gzip, pinned rather than inherited. On the Ubuntu runner this macro is not
# defined at all (rpm 4.18.2: `rpm --eval '%{_binary_payload}'` prints itself
# back), so rpmbuild falls through to its compiled-in default, which today
# happens to be this same value. A Fedora build host is different: installing
# `redhat-rpm-config`, which any machine that builds rpms there has, changes
# it to `w19.zstdio`. Which of those a package gets should not turn on which
# distribution's rpm the runner carries: zstd needs rpm 4.14 or later to open,
# every rpm reads gzip, and the payload is one seven-megabyte file.
# build-rpm.sh checks the result.
%global _binary_payload w9.gzdio

Name:           cairn
Version:        %{cairn_version}
Release:        %{cairn_release}
Summary:        Research network where verified results are the unit of account
License:        Apache-2.0
URL:            %{cairn_homepage}
Packager:       %{cairn_maintainer}

# The dependency generator reads ELF headers for needed libraries. A static
# binary has none, so there is nothing for it to find -- and nothing it should
# be allowed to invent.
AutoReqProv:    no

# Weak, not hard, for the reasons build-deb.sh gives at length: a node wants
# both, a light client that only checks proofs needs neither. dnf installs weak
# dependencies by default -- fedora:latest pulls in both -- and rpm 4.12
# introduced them, so RHEL 7 cannot parse this package at all.
#
# Unversioned, though the verifiers in this repository need Python 3.9. That
# is a fact about those verifiers, not about cairn: an objective pins whatever
# code it likes. It does mean RHEL 8, whose python3 is 3.6, installs and runs
# this package and then reports the launch log's Python claims as unavailable;
# docs/install.md says so, and the install test runs on RHEL 9's family.
Recommends:     bubblewrap
Recommends:     python3

%description
One binary. The CLI, the MCP server (cairn mcp), the p2p daemon (cairn p2p),
the HTTP publisher (cairn serve) and the complete local node (cairn run, which
also serves the embedded reader) are subcommands of it.

Anyone can independently re-derive every settled result from the log alone:
"cairn audit" re-runs each objective's pinned verifier against the artifact
that claimed its bounty, and trusts neither the operator nor the server the
log came from.

Statically linked, so it has no library dependencies and runs on any release
of any distribution. It installs no service and creates no user: a node's
state lives wherever the operator starts it.

%install
rm -rf "%{buildroot}"
install -D -m 0755 "%{cairn_binary}" "%{buildroot}/usr/bin/cairn"
install -D -m 0644 "%{cairn_repo}/LICENSE" "%{buildroot}/usr/share/licenses/cairn/LICENSE"
install -D -m 0644 "%{cairn_repo}/CHANGELOG.md" "%{buildroot}/usr/share/doc/cairn/CHANGELOG.md"

# Paths written out rather than spelled %{_bindir} and %{_licensedir}. The
# macros belong to the machine that *builds*, which is Ubuntu, and Debian's rpm
# does not define all of them the way Fedora's does; the paths belong to the
# machine that installs. %attr because the build runs unprivileged and the
# files would otherwise be recorded as owned by the runner's user.
%files
%attr(0755,root,root) /usr/bin/cairn
%dir %attr(0755,root,root) /usr/share/licenses/cairn
%license %attr(0644,root,root) /usr/share/licenses/cairn/LICENSE
%dir %attr(0755,root,root) /usr/share/doc/cairn
%doc %attr(0644,root,root) /usr/share/doc/cairn/CHANGELOG.md
