use network_analyzer::analyzer::Analyzer;
use network_analyzer::select_device;

fn main() {
    let mut input = String::new();

    //Select the device from all the network devices of the pc
    println!("Select the device to sniff:");
    let device_name = select_device();

    //We want to update the aggregated data every 5 seconds
    let timer:u64=5;

    //Into the file analysis_report.md
    let filename = String::from("analysis_report");

    //The analyzer struct instantiates and manages for you one parser, one aggregator and one report writer
    //so that you can just specify the device you want to collect aggregated data from and the time interval
    //between each update of the report file [filename].md
    {
        let a_one=Analyzer::new(&device_name, &filename, timer);

        println!("Analysis of device {} started, enter anything to go to the PAUSE step",device_name);
        std::io::stdin().read_line(&mut input).unwrap();


        //I can also decide to pause the sniffing process
        a_one.pause();

        println!("Analysis of device {} PAUSED, enter anything to go to the RESUME step",device_name);
        std::io::stdin().read_line(&mut input).unwrap();


        //So that the threads of parser and aggregator are still available but doing nothing while I do something else
        //I can resume it
        a_one.resume();

        println!("Analysis of device {} RESUMED, enter anything to go to the STOP step",device_name);
        std::io::stdin().read_line(&mut input).unwrap();
    }

    //When a_one is dropped all threads stop
    println!("Analysis of device {} STOPPED, enter anything to end the program",device_name);
    std::io::stdin().read_line(&mut input).unwrap();


}