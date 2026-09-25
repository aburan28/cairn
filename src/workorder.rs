//! A work order is an objective that pays for verified units of a declared
//! search, not for hours. Parsing lives here so a volunteer can see what a
//! unit is before any consensus field exists.
//!
//! The block is advisory until both implementations agree to admit it. Nothing
//! in this module settles a balance.

use crate::canonical::Value;

/// How a unit is checked. Each one already exists somewhere in the crate;
/// this names which one a work order intends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    /// Pinned output checker, as piecework does today.
    Checker,
    /// k-of-n replication with bonded attestations.
    Replication,
    /// Sampled re-execution, as the orbit audit does.
    Sample,
    /// Bisection over a stepper, as `challenge` does.
    Bisection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkOrder {
    pub strategy: Strategy,
    pub unit: String,
    pub price_per_unit: u64,
    pub cpu_cores: u32,
    pub ram_mib: u64,
    pub vram_mib: u64,
}

pub fn parse(value: &Value) -> Option<WorkOrder> {
    let strategy = match value.get("strategy").and_then(Value::as_str)? {
        "checker" => Strategy::Checker,
        "replication" => Strategy::Replication,
        "sample" => Strategy::Sample,
        "bisection" => Strategy::Bisection,
        _ => return None,
    };
    let unit = value.get("unit").and_then(Value::as_str)?.to_string();
    let price_per_unit =
        u64::try_from(value.get("price_per_unit").and_then(Value::as_i128)?).ok()?;
    let cpu_cores =
        u32::try_from(value.get("cpu_cores").and_then(Value::as_i128).unwrap_or(0)).ok()?;
    let ram_mib = u64::try_from(value.get("ram_mib").and_then(Value::as_i128).unwrap_or(0)).ok()?;
    let vram_mib =
        u64::try_from(value.get("vram_mib").and_then(Value::as_i128).unwrap_or(0)).ok()?;
    Some(WorkOrder {
        strategy,
        unit,
        price_per_unit,
        cpu_cores,
        ram_mib,
        vram_mib,
    })
}

/// A unit is assigned only to a node whose *proved* capacity covers it.
/// Self-reported telemetry is not an argument here.
pub fn fits(order: &WorkOrder, proved_vram_mib: u64, proved_ram_mib: u64) -> bool {
    proved_vram_mib >= order.vram_mib && proved_ram_mib >= order.ram_mib
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_gpu_unit_is_not_assigned_to_a_node_that_has_not_proved_the_vram() {
        let order = WorkOrder {
            strategy: Strategy::Checker,
            unit: "orbit".into(),
            price_per_unit: 1,
            cpu_cores: 1,
            ram_mib: 1024,
            vram_mib: 24_576,
        };
        assert!(!fits(&order, 8_192, 65_536));
        assert!(fits(&order, 24_576, 65_536));
    }
}
