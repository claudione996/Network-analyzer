use crate::modules::analyzer::Analyzer;

mod modules;

fn main() {
    //scheda di binco: "\\Device\\NPF_{CD484432-E2CB-46E8-8FCC-3D919CF3533E}"
    // scheda di giovanni: "\\Device\\NPF_{DFADCF5E-E518-4EB5-A225-3126223CB9A2}"
    let a=Analyzer::new("\\Device\\NPF_{CD484432-E2CB-46E8-8FCC-3D919CF3533E}", "report", 15);
    a.choice_loop();

}
