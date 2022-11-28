use Network_analyzer::analyzer::Analyzer;
use Network_analyzer::select_device;

fn main() {

    //select the device from all the network devices of the pc
    println!("Select the device to sniff:");
    let device_name = select_device();

    //we want to update the aggregated data every 5 seconds
    let timer:u64=5;

    //into the file analysis_report.md
    let filename = String::from("analysis_report");

    //The analyzer struct instantiates and manages for you one parser, one aggregator and one report writer
    //so that you can just specify the device you want to collect aggregated data from and the time interval
    //between each update of the report file [filename].md
    let a_one=Analyzer::new(&device_name, &filename, timer);

    println!("analysis of device {} started, enter anything to go to the PAUSE step",device_name);
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();


    //i can also decide to pause the sniffing process
    a_one.pause();

    println!("analysis of device {} PAUSED, enter anything to go to the RESUME step",device_name);
    std::io::stdin().read_line(&mut input).unwrap();


    //so that the threads of parser and aggregator are still available but doing nothing while i do something else
    //i can resume it
    a_one.resume();

    println!("analysis of device {} RESUMED, enter anything to go to the STOP step",device_name);
    std::io::stdin().read_line(&mut input).unwrap();

    //or i can stop completely all threads to never use it again
    a_one.exit();
    println!("analysis of device {} STOPPED, enter anything to end the program",device_name);
    std::io::stdin().read_line(&mut input).unwrap();


}