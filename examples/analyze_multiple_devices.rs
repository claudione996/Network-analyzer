use std::io::stdin;
use Network_analyzer::analyzer::Analyzer;
use Network_analyzer::select_device;

fn main() {

    //select the device from all the network devices of the pc
    println!("Select the first device to sniff:");
    let device_name_1 = select_device();
    println!("Select the second device to sniff:");
    let device_name_2 = select_device();

    //we want to update the aggregated data report every 5 and 3 seconds respectively for device 1 and 2
    let timer_1:u64=5;
    let timer_2:u64=3;

    //into the file analysis_report.md
    let filename_1 = String::from("multi_analysis_report_1");
    let filename_2 = String::from("multi_analysis_report_2");

    //Each analyzer manages its own parser, aggregator and report writer so that
    //multiple analyzers can be instantiated and run at the same time
    let a_1=Analyzer::new(&device_name_1, &filename_1, timer_1);
    let a_2=Analyzer::new(&device_name_2, &filename_2, timer_2);

    println!("analysis of both devices started, enter anything to go to the PAUSE step");
    let mut input = String::new();
    stdin().read_line(&mut input).unwrap();


    //i can also decide to pause the sniffing process of one one analyzer
    //and lat the other one continue to work
    a_1.pause();

    println!("analysis of device 1 PAUSED, enter anything to go to the EXIT step");
    stdin().read_line(&mut input).unwrap();

    a_1.exit();
    a_2.exit();
    println!("analysis of both devices STOPPED, enter anything to end the program");
    stdin().read_line(&mut input).unwrap();


}