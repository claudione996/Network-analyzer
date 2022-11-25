use std::thread::sleep;
use std::time;
use Network_analyzer::report_writer::ReportWriter;
use Network_analyzer::select_device;
use Network_analyzer::socket_listener::SocketListener;

fn main() {

    //selecting the device from all the network devices of the pc
    println!("Select the device to sniff:");
    let device_name = select_device();

    //instantiating a socket listener to get aggregated data from the device
    let sl : SocketListener = SocketListener::new(&device_name);

    //getting the reference to the aggregated data in the same way i do with the aggregator
    let mut agg_data = sl.get_aggregated_data();

    //the report writer struct runs a thread that will write the aggregated data collected by an aggregator
    //into a [report_path].md file in a periodic way each [rewrite_time] seconds
    let report_path = String::from("testFile");
    let rewrite_time:u64=3;
    let report_writer = ReportWriter::new(report_path, rewrite_time, sl.get_aggregated_data());

    //since the report_writer works on its own thread, the report will be written even while this main thread sleeps
    let time  = time::Duration::from_secs(6);
    println!("sleeping waiting for some rewrites of the testFile.md");
    sleep(time);

    //if i want i can also switch the writing to a new file
    report_writer.set_report_path("secondTestFile".to_string());
    //and change the rewrite_time
    report_writer.set_rewrite_time(1);

    println!("switched to secondTestFile.md with rewrite time 1s");
    println!("sleeping waiting for some rewrites of the secondTestFile.md");
    sleep(time);
    println!("end of example");


}