use std::io;
use crate::modules::analyzer::Analyzer;

mod modules;

fn main() {
    //scheda di binco: "\\Device\\NPF_{CD484432-E2CB-46E8-8FCC-3D919CF3533E}"
    // scheda di giovanni: "\\Device\\NPF_{DFADCF5E-E518-4EB5-A225-3126223CB9A2}"
    //scheda di claudione: "en0"
    let a=Analyzer::new("\\Device\\NPF_{CD484432-E2CB-46E8-8FCC-3D919CF3533E}", "report", 15);

    loop {
        println!("options: 1 (pause), 2 (resume), 3 (exit)");
        let mut input_line = String::new();
        io::stdin()
            .read_line(&mut input_line)
            .expect("Failed to read line");
        let mut number: usize = input_line.trim().parse().expect("Input not an integer");

        match number{
            1 => a.pause(),
            2 => a.resume(),
            3 => {a.exit(); break;}
            _ => println!("invalid input: select either 1 (to pause), 2 (to resume) or 3 (to end the program)")
        }

    }

}
