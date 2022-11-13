use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{channel, Sender};
use crate::modules::parsedpacket::ParsedPacket;
use crate::modules::report_entry::{Connection, ConnectionMetadata};


/// aggregated data entry structure: {Key: (src_ip, dest_ip, src_port, dest_port, protocol), Value: (size, first_timestamp, last_timestamp)}
#[derive(Clone)]
pub struct Aggregator{
    tx: Sender<ParsedPacket>,
    aggregated_data: Arc<Mutex<HashMap<Connection,ConnectionMetadata>>>
}
impl Aggregator{
    pub fn new() -> Self {

        let(tx,rx) = channel::<ParsedPacket>();

        //declare an hashmap with key as tuple of (destination_ip,port) and value as tuple of (protocol, size, first_timestamp, last_timestamp)
        let mut aggregated_data = Arc::new(Mutex::new(HashMap::<Connection,ConnectionMetadata>::new()));
        let mut aggregated_data_clone = Arc::clone(&aggregated_data);

        std::thread::spawn( move || {

            println!("Aggregator thread started");

            let mut loop1 = true;
            while loop1 {
                let msg = rx.recv();
                match msg {
                    Err(e) => {
                        println!("Error: {}", e);
                        loop1 = false;
                    },
                    Ok(p) => {
                        println!("processing: {:?}", p);

                        let key = Connection::new(p.source_ip, p.destination_ip, p.source_port, p.destination_port, p.protocol);
                        let mut aggregated_map = aggregated_data_clone.lock().unwrap();

                        if aggregated_map.contains_key(&key) {
                            println!("Key already exists, updating value");
                            let mut value = aggregated_map.get_mut(&key).unwrap();
                            (*value).size = p.size + (*value).size;
                            (*value).last_timestamp = p.timestamp;
                            //aggregated_map.insert(key,(*value).clone());
                        } else {
                            println!("Key does not exist, inserting new value");
                            let value = ConnectionMetadata::new(p.size,p.timestamp.clone(),p.timestamp);
                            aggregated_map.insert(key,value);
                        }

                    }
                }
            }
        });
        Aggregator { tx, aggregated_data }
    }
    pub fn send(&self, packet: ParsedPacket){
        self.tx.send(packet).unwrap();
    }
    pub fn get_aggregated_data(&self) -> Arc<Mutex<HashMap<Connection,ConnectionMetadata>>> {
        Arc::clone(&self.aggregated_data)
    }
    pub fn get_sender(&self) -> Sender<ParsedPacket> {
        self.tx.clone()
    }
}
