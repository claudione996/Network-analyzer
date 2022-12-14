use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time;
use network_analyzer::aggregator::Aggregator;
use network_analyzer::parser::Parser;
use network_analyzer::report_entry::{Connection, ConnectionMetadata};
use network_analyzer::select_device;

fn main() {

    //declaring the aggregator
    let aggregator= Aggregator::new();

    //obtaining the Sender to use to send packets to the Aggregator
    let aggregator_tx= aggregator.get_sender();

    //select the device from all the network devices of the pc
    println!("Select the device to sniff:");
    let device_name = select_device();

    //initialize the parser with the aggregator_tx Sender so that it will send the parsed packets to the aggregator
    let _parser= Parser::new(&device_name, aggregator_tx.clone());

    //here i get the reference to the aggregated data produced and updated by the aggregator each time it receives a parsed packet
    let aggregated_data: Arc<Mutex<HashMap<Connection, ConnectionMetadata>>> = aggregator.get_aggregated_data();

    let time  = time::Duration::from_secs(5);
    loop {
        //i will print the aggregated data each 5s
        sleep(time);
        {
            let aggregated_data = aggregated_data.lock().unwrap();
            for (conn,data) in aggregated_data.iter() {
                println!("{}{}",conn,data);
            }
        }
        //here i release the lock onto the aggregated_data to let the aggregator write into it
        //while this thread sleeps
    }

}