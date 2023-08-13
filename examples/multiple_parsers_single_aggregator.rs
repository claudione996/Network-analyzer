use std::collections::HashMap;
use std::sync::{Arc, RwLock};
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

    //select the first device from all the network devices of the pc
    println!("Select the first device to sniff:");
    let first_device_name = select_device();
    //select the second device from all the network devices of the pc
    println!("Select the second device to sniff:");
    let second_device_name = select_device();
    //I create the parsers listening to the devices and both sending the parsed packets to the same aggregator
    let _parser1 = Parser::new(&first_device_name, aggregator_tx.clone());
    let _parser2 = Parser::new(&second_device_name, aggregator_tx.clone());

    //Here I get the reference to the aggregated data produced and updated by the aggregator each time it receives a parsed packet
    let aggregated_data: Arc<RwLock<HashMap<Connection, ConnectionMetadata>>> = aggregator.get_aggregated_data();

    let time  = time::Duration::from_secs(5);
    loop {
        //I will print the aggregated data each 5s
        sleep(time);
        {
            let aggregated_data = aggregated_data.read().unwrap();
            for (conn,data) in aggregated_data.iter() {
                println!("{}{}",conn,data);
            }
        }
    }

}