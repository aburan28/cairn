//! Operator-set compute estimates, separate from verified-result rewards.
//!
//! There is no universal AVX-512 multiplier: a rate is scoped to a named
//! workload and an exact CPU predicate. All amounts use integer millionths of
//! the card's unit. Quotes reserve nothing and never debit a ledger.

use crate::canonical::Value;
use crate::hardware::{number, object, text, CpuRequirements};
use crate::scheduling::ResourceOffer;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpuRate {
    pub id: String,
    pub workload: String,
    pub cpu: CpuRequirements,
    pub cpu_second_microunits: u64,
    pub memory_gib_second_microunits: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateCard {
    pub unit: String,
    pub rates: Vec<CpuRate>,
}

fn required_number(value: &Value, field: &str) -> Result<u64, String> {
    number(value, field)?.ok_or_else(|| format!("{field} is required"))
}
fn required_text(value: &Value, field: &str) -> Result<String, String> {
    text(value, field)?.ok_or_else(|| format!("{field} is required"))
}
fn only(value: &Value, fields: &[&str]) -> Result<(), String> {
    if let Some(field) = object(value, "pricing")?
        .keys()
        .find(|field| !fields.contains(&field.as_str()))
    {
        return Err(format!("unknown pricing field {field:?}"));
    }
    Ok(())
}

impl RateCard {
    /// Rates are ordered: put workload-specific hardware premiums before a
    /// generic fallback. Exposing the chosen id makes that choice reviewable.
    pub fn from_value(value: &Value) -> Result<Self, String> {
        only(value, &["unit", "rates"])?;
        let unit = required_text(value, "unit")?;
        let rates = value
            .get("rates")
            .and_then(Value::as_array)
            .filter(|rates| !rates.is_empty() && rates.len() <= 64)
            .ok_or("rates must contain 1-64 entries")?;
        let mut ids = std::collections::BTreeSet::new();
        let rates = rates
            .iter()
            .map(|rate| {
                only(
                    rate,
                    &[
                        "id",
                        "workload",
                        "cpu",
                        "cpu_second_microunits",
                        "memory_gib_second_microunits",
                    ],
                )?;
                let id = required_text(rate, "id")?;
                if !ids.insert(id.clone()) {
                    return Err(format!("duplicate rate id {id}"));
                }
                Ok(CpuRate {
                    id,
                    workload: required_text(rate, "workload")?,
                    cpu: rate
                        .get("cpu")
                        .map(CpuRequirements::from_value)
                        .transpose()?
                        .unwrap_or_default(),
                    cpu_second_microunits: required_number(rate, "cpu_second_microunits")?,
                    memory_gib_second_microunits: required_number(
                        rate,
                        "memory_gib_second_microunits",
                    )?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(Self { unit, rates })
    }

    pub fn to_value(&self) -> Value {
        Value::object([
            ("unit", Value::string(&self.unit)),
            (
                "rates",
                Value::array(self.rates.iter().map(|rate| {
                    Value::object([
                        ("id", Value::string(&rate.id)),
                        ("workload", Value::string(&rate.workload)),
                        ("cpu", rate.cpu.to_value()),
                        (
                            "cpu_second_microunits",
                            Value::Int(i128::from(rate.cpu_second_microunits)),
                        ),
                        (
                            "memory_gib_second_microunits",
                            Value::Int(i128::from(rate.memory_gib_second_microunits)),
                        ),
                    ])
                })),
            ),
        ])
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuoteRequest {
    pub workload: String,
    pub cpu_millis: u64,
    pub memory_mb: u64,
    pub duration_ms: u64,
    pub cpu: CpuRequirements,
}

impl QuoteRequest {
    pub fn from_value(value: &Value) -> Result<Self, String> {
        only(
            value,
            &[
                "host",
                "workload",
                "cpus",
                "cpu_millis",
                "memory_mb",
                "duration_ms",
                "cpu",
            ],
        )?;
        let request = Self {
            workload: required_text(value, "workload")?,
            cpu_millis: match (number(value, "cpus")?, number(value, "cpu_millis")?) {
                (Some(cpus), None) => cpus
                    .checked_mul(1000)
                    .ok_or("cpus overflows CPU milliseconds")?,
                (None, Some(millis)) => millis,
                _ => return Err("provide exactly one of cpus or cpu_millis".into()),
            },
            memory_mb: required_number(value, "memory_mb")?,
            duration_ms: required_number(value, "duration_ms")?,
            cpu: value
                .get("cpu")
                .map(CpuRequirements::from_value)
                .transpose()?
                .unwrap_or_default(),
        };
        if request.cpu_millis == 0 || request.duration_ms == 0 {
            return Err("CPU allocation and duration_ms must be positive".into());
        }
        Ok(request)
    }
    fn to_value(&self) -> Value {
        Value::object([
            ("workload", Value::string(&self.workload)),
            ("cpu_millis", Value::Int(i128::from(self.cpu_millis))),
            ("memory_mb", Value::Int(i128::from(self.memory_mb))),
            ("duration_ms", Value::Int(i128::from(self.duration_ms))),
            ("cpu", self.cpu.to_value()),
        ])
    }
}

/// Round up once, after summing CPU and memory costs in checked u128. Unknown
/// capacity, missing tariffs, and overflow are errors rather than free work.
pub fn quote(offer: &ResourceOffer, request: &QuoteRequest) -> Result<Value, String> {
    if request.cpu_millis == 0 || request.duration_ms == 0 {
        return Err("CPU allocation and duration_ms must be positive".into());
    }
    if offer
        .cpus
        .is_none_or(|n| u128::from(n) * 1000 < u128::from(request.cpu_millis))
        || offer.cpu_millis.is_some_and(|n| n < request.cpu_millis)
        || (request.memory_mb > 0 && offer.memory_mb.is_none_or(|n| n < request.memory_mb))
        || offer.concurrency == Some(0)
        || !request.cpu.matches(offer.cpu.as_ref())
    {
        return Err("host does not offer the requested capacity or usable CPU features".into());
    }
    // Even generic tariffs need a sampled profile for reproducible experiments.
    let cpu = offer
        .cpu
        .as_ref()
        .ok_or("host has no CPU profile; refresh its agent")?;
    let card = offer
        .pricing
        .as_ref()
        .ok_or("host has not published a compute rate card")?;
    let rate = card
        .rates
        .iter()
        .find(|rate| rate.workload == request.workload && rate.cpu.matches(Some(cpu)))
        .ok_or("no rate for this workload and CPU profile")?;
    let cost = || -> Option<u128> {
        let cpu = u128::from(request.cpu_millis)
            .checked_mul(u128::from(rate.cpu_second_microunits))?
            .checked_mul(1024)?;
        let memory = u128::from(request.memory_mb)
            .checked_mul(u128::from(rate.memory_gib_second_microunits))?
            .checked_mul(1000)?;
        cpu.checked_add(memory)?
            .checked_mul(u128::from(request.duration_ms))?
            .checked_add(1_024_000_000 - 1)
            .map(|n| n / 1_024_000_000)
    };
    let total = cost()
        .and_then(|n| u64::try_from(n).ok())
        .ok_or("compute quote overflows u64 microunits")?;
    let terms = card.to_value();
    Ok(Value::object([
        ("unit", Value::string(&card.unit)), ("amount_microunits", Value::Int(i128::from(total))),
        ("rate_id", Value::string(&rate.id)), ("rate_card_id", Value::string(terms.digest())),
        ("rate_card", terms), ("request", request.to_value()), ("cpu", cpu.to_value()),
        ("cpu_profile_id", Value::string(cpu.to_value().digest())),
        ("note", Value::string("An estimate at operator-set rates for requested allocations and duration, in millionths of the named unit. Hardware and rates are host reports, not independently verified. No reservation, debit, result reward, or measured-throughput guarantee. GPU, storage, and network charges are not included.")),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hardware::CpuProfile;
    fn offer() -> ResourceOffer {
        ResourceOffer {
            cpus: Some(8), memory_mb: Some(8192), concurrency: Some(1),
            cpu: Some(CpuProfile { arch: "x86_64".into(), features: vec!["avx512f".into()], ..CpuProfile::default() }),
            pricing: Some(RateCard::from_value(&Value::from_json(r#"{"unit":"USD","rates":[{"id":"avx512","workload":"boomer-v1","cpu":{"features":["avx512f"]},"cpu_second_microunits":3,"memory_gib_second_microunits":2},{"id":"baseline","workload":"boomer-v1","cpu_second_microunits":1,"memory_gib_second_microunits":2}]}"#).unwrap()).unwrap()),
            ..ResourceOffer::default()
        }
    }
    fn request() -> QuoteRequest {
        QuoteRequest {
            workload: "boomer-v1".into(),
            cpu_millis: 2000,
            memory_mb: 512,
            duration_ms: 1500,
            cpu: CpuRequirements::default(),
        }
    }
    #[test]
    fn prices_requested_resources_once_with_explicit_hardware_rates() {
        let mut host = offer();
        let price = quote(&host, &request()).unwrap();
        assert_eq!(
            price.get("amount_microunits").and_then(Value::as_u64),
            Some(11)
        ); // (6 + 1) * 1.5, rounded up
        assert_eq!(price.get("rate_id").and_then(Value::as_str), Some("avx512"));
        host.cpu.as_mut().unwrap().features.clear();
        assert_eq!(
            quote(&host, &request())
                .unwrap()
                .get("amount_microunits")
                .and_then(Value::as_u64),
            Some(5)
        );
        let mut tiny = request();
        tiny.duration_ms = 1;
        tiny.cpu_millis = 1000;
        tiny.memory_mb = 1;
        assert_eq!(
            quote(&host, &tiny)
                .unwrap()
                .get("amount_microunits")
                .and_then(Value::as_u64),
            Some(1)
        );
    }
    #[test]
    fn missing_rates_capacity_and_overflow_are_never_free_quotes() {
        let mut host = offer();
        let mut req = request();
        req.workload = "another-benchmark".into();
        assert!(quote(&host, &req).is_err());
        req = request();
        req.cpu.features.push("avx512bw".into());
        assert!(quote(&host, &req).is_err());
        req = request();
        req.cpu_millis = 9000;
        assert!(quote(&host, &req).is_err());
        host.memory_mb = None;
        assert!(quote(&host, &request()).is_err());
        host = offer();
        host.pricing = None;
        assert!(quote(&host, &request()).is_err());
        host = offer();
        host.cpu_millis = Some(500);
        assert!(quote(&host, &request()).is_err());
        req = request();
        req.cpu_millis = 500;
        assert!(quote(&host, &req).is_ok());
        host = offer();
        host.cpus = Some(u64::MAX);
        host.pricing.as_mut().unwrap().rates[0].cpu_second_microunits = u64::MAX;
        req = request();
        req.cpu_millis = u64::MAX;
        req.duration_ms = u64::MAX;
        assert!(quote(&host, &req).is_err());
    }
    #[test]
    fn tariff_typos_duplicates_floats_and_implicit_zero_prices_are_refused() {
        for bad in [
            r#"{"unit":"USD","rates":[]}"#,
            r#"{"unit":"USD","rates":[{"id":"x","workload":"w","cpu_second_microunits":1}]}"#,
            r#"{"unit":"USD","rates":[{"id":"x","workload":"w","cpu_second_microunits":1,"memory_gib_second_microunits":0,"mulitplier":2}]}"#,
        ] {
            assert!(RateCard::from_value(&Value::from_json(bad).unwrap()).is_err());
        }
        let card = offer().pricing.unwrap();
        assert_eq!(RateCard::from_value(&card.to_value()).unwrap(), card);
        let mut duplicate = card.clone();
        duplicate.rates.push(card.rates[0].clone());
        assert!(RateCard::from_value(&duplicate.to_value()).is_err());
        assert!(Value::from_json(r#"{"unit":"USD","rates":[{"id":"x","workload":"w","cpu_second_microunits":0.1,"memory_gib_second_microunits":0}]}"#).is_err());
    }
}
