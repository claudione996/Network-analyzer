use std::{io, num::ParseIntError};
use crate::modules::{analyzer::Analyzer, lib::select_device};

mod modules;

fn main() {
    //scheda di binco: "\\Device\\NPF_{CD484432-E2CB-46E8-8FCC-3D919CF3533E}"
    // scheda di giovanni: "\\Device\\NPF_{DFADCF5E-E518-4EB5-A225-3126223CB9A2}"
    //scheda di claudione: "en0"
    //scheda di paolo: "\\Device\\NPF_{CA1DFCEA-2C68-4269-9347-4B04CB3E6420}"

    println!("Select the device to sniff:");
    let device_name = select_device();
    
    println!("\nSelect the report time interval (s):");
    let time: usize;
    loop{
        let mut input_line = String::new();
        io::stdin()
            .read_line(&mut input_line)
            .expect("Failed to read line");
        let time_res: Result<usize, ParseIntError> = input_line.trim().parse();
        match time_res{
            Ok(x) => {time = x; 
                            break;},
            Err(_) => {println!("Time interval must be a number. Please insert again:")}
        }
    }
    println!("Time interval selected: {time} s");

    println!("\nChoose the name of the file where you want the report to be saved:");
    let mut name_input = String::new();
    io::stdin()
            .read_line(&mut name_input)
            .expect("Failed to read line");
    let name_input = name_input.trim();
    println!("Report will be saved in report/{name_input}.txt\n");

    let a=Analyzer::new(&device_name, name_input, time as u64);

    loop {
        println!("options: 1 (pause), 2 (resume), 3 (exit)");
        let mut input_line = String::new();
        io::stdin()
            .read_line(&mut input_line)
            .expect("Failed to read line");
        let number: usize = input_line.trim().parse().expect("Input not an integer");

        match number{
            1 => a.pause(),
            2 => a.resume(),
            3 => {a.exit(); break;}
            _ => println!("invalid input: select either 1 (to pause), 2 (to resume) or 3 (to end the program)")
        }

    }

}
