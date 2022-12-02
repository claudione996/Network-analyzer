use std::io::stdin;
use network_analyzer::analyzer::Analyzer;
use network_analyzer::select_device;

fn main() {
    let mut input = String::new();

    //Select the device from all the network devices of the pc
    println!("Select the first device to sniff:");
    let device_name_1 = select_device();
    println!("Select the second device to sniff:");
    let device_name_2 = select_device();

    //We want to update the aggregated data report every 5 and 3 seconds respectively for device 1 and 2
    let timer_1:u64=5;
    let timer_2:u64=3;

    //Into the file analysis_report.md
    let filename_1 = String::from("multi_analysis_report_1");
    let filename_2 = String::from("multi_analysis_report_2");

    //Each analyzer manages its own parser, aggregator and report writer so that
    //multiple analyzers can be instantiated and run at the same time
    let a_1=Analyzer::new(&device_name_1, &filename_1, timer_1);
    {
        let _a_2=Analyzer::new(&device_name_2, &filename_2, timer_2);

        println!("Analysis of both devices started, enter anything to go to the PAUSE step");
        stdin().read_line(&mut input).unwrap();


        //I can also decide to pause the sniffing process of one analyzer
        //and let the other one continue to work
        a_1.pause();

        println!("Analysis of device 1 PAUSED, enter anything to end the program");
        stdin().read_line(&mut input).unwrap();
    }
    println!("a_2 dropped: analysis STOPPED, thread killed, enter anything to end the program");
    stdin().read_line(&mut input).unwrap();

    println!("Analysis of both devices STOPPED");

}