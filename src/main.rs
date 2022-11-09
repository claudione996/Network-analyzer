use crate::modules::analyzer::Analyzer;

mod modules;

fn main() {

    let a=Analyzer::new("\\Device\\NPF_{DFADCF5E-E518-4EB5-A225-3126223CB9A2}", "report", 15);
    a.choice_loop();

}
