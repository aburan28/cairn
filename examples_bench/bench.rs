fn main() {
    use proofwork::incentive::{design::Report, NodeParams};
    for nodes in [8u32, 20, 50, 100] {
        let p = NodeParams { nodes, committee: nodes.min(21), threshold: nodes.min(21)/2+1, ..NodeParams::reference() };
        if p.validate().is_err() { println!("{nodes}: invalid"); continue; }
        let t = std::time::Instant::now();
        for _ in 0..5 { let _ = Report::of(&p).map(|r| r.passes()); }
        println!("nodes={nodes:4}  {:?} per report", t.elapsed()/5);
    }
}
