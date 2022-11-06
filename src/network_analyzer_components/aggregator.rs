use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{channel, Sender};
use crate::ParsedPacket;

#[derive(Clone)]
pub struct Aggregator{
    tx: Sender<ParsedPacket>,
    aggregated_data: Arc<Mutex<HashMap<(String,usize),(String,usize,usize,usize)>>>
}
impl Aggregator{
    pub fn new() -> Self {

        let(tx,rx) = channel::<ParsedPacket>();

        //declare an hashmap with key as tuple of (destination_ip,port) and value as tuple of (protocol, size, first_timestamp, last_timestamp)
        let mut aggregated_data = Arc::new(Mutex::new(HashMap::<(String,usize),(String,usize,usize,usize)>::new()));
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

                        let key = (p.destination_ip,p.destination_port);
                        let mut aggregated_map = aggregated_data_clone.lock().unwrap();
                        if aggregated_map.contains_key(&key) {
                            println!("Key already exists, updating value");
                            let value = aggregated_map.get(&key).unwrap().clone();
                            aggregated_map.insert(key,(p.protocol,value.1 + p.size,value.2.clone(),p.timestamp));
                        } else {
                            println!("Key does not exist, inserting new value");
                            let value = (p.protocol,p.size,p.timestamp.clone(),p.timestamp);
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
    pub fn get_aggregated_data(&self) -> Arc<Mutex<HashMap<(String,usize),(String,usize,usize,usize)>>> {
        Arc::clone(&self.aggregated_data)
    }
}
