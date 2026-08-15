//! `proofwork-arena` — run the adversarial scenarios and print the payoffs.
//!
//! A separate binary rather than a `proofwork` subcommand, for the same reason
//! `proofwork-serve` is one: this drives dozens of nodes through hundreds of
//! epochs and takes seconds to minutes, which is not a shape the record CLI
//! should grow.
//!
//!   proofwork-arena              # every scenario, seed 1
//!   proofwork-arena --seed 7     # a different draw
//!
//! Every number it prints except the modelled costs is read out of balances a
//! real `Node` settled.

use proofwork::arena::{scenarios, Costs};

fn main() {
    let mut seed = 1u64;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--seed" => {
                seed = args
                    .next()
                    .and_then(|text| text.parse().ok())
                    .unwrap_or(seed);
            }
            "-h" | "--help" => {
                println!("usage: proofwork-arena [--seed N]");
                return;
            }
            other => {
                eprintln!("unknown option {other:?}");
                std::process::exit(2);
            }
        }
    }
    let trials = scenarios::all(seed);
    print!("{}", scenarios::report(&trials, Costs::default()));

    let open: Vec<&str> = trials
        .iter()
        .filter(|trial| matches!(trial.verdict(), proofwork::arena::Verdict::StillPays { .. }))
        .map(|trial| trial.attack.as_str())
        .collect();
    let inert: Vec<&str> = trials
        .iter()
        .filter(|trial| matches!(trial.verdict(), proofwork::arena::Verdict::NeverPaid { .. }))
        .map(|trial| trial.attack.as_str())
        .collect();
    if !inert.is_empty() {
        println!("inert (measured nothing): {}", inert.join(", "));
    }
    if open.is_empty() {
        println!("no attack in this set is profitable against its defence");
    } else {
        println!("still profitable: {}", open.join(", "));
        std::process::exit(1);
    }
}
