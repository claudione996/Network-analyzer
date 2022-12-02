use std::{io, num::ParseIntError};
use network_analyzer::analyzer::Analyzer;
use network_analyzer::select_device;


fn main() {

    println!("Welcome to Network Analyzer!\n");

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
    println!("Report will be saved in 'report/{name_input}.md'\n");

    let a=Analyzer::new(&device_name, name_input, time as u64);

    loop {
        println!("Options");
        println!("1 - PAUSE");
        println!("2 - RESUME");
        println!("3 - EXIT");
        let mut input_line = String::new();
        io::stdin()
            .read_line(&mut input_line)
            .expect("Failed to read line");

        let opt_res: Result<usize, ParseIntError> = input_line.trim().parse();
         match opt_res{
            Ok(number) => {
                match number{
                    1 => a.pause(),
                    2 => a.resume(),
                    3 => {println!("EXIT: Stopping Network Analyzer"); break;}
                    _ => println!("Invalid choice: select either 1 (PAUSE), 2 (RESUME) or 3 (EXIT)")
                }
            },
            Err(_) => {println!("Option choice must be a number!")}
        }

    }

}
