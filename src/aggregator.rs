use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{channel, RecvError, Sender};
use crate::parsed_packet::ParsedPacket;
use crate::report_entry::{Connection, ConnectionMetadata};


/// Struct that aggregates data from received [ParsedPacket] into an HashMap which has as a key: [Connection] and as a value: [ConnectionMetadata]
///
/// # Examples
/// Basic usage:
/// ```rust
/// use Network_analyzer::aggregator::Aggregator;
/// use Network_analyzer::parser::Parser;
///
/// let aggregator=Aggregator::new();
///
/// let aggregator_tx=aggregator.get_sender();
///
/// let parser=Parser::new("eth0", aggregator_tx.clone());
/// ```
///
/// Advanced usage: create multiple aggregators for multiple parsers listening on different devices
/// ```rust
/// use Network_analyzer::aggregator::Aggregator;
/// use Network_analyzer::parser::Parser;
///
/// let aggregator_one=Aggregator::new();
///
/// let aggregator_tx_one=aggregator_one.get_sender();
///
/// let parser_one=Parser::new("eth0", aggregator_tx_one.clone());
///
///
/// let aggregator_two=Aggregator::new();
///
/// let aggregator_tx_two=aggregator_two.get_sender();
///
/// let parser_two=Parser::new("eth1", aggregator_tx_two.clone());
///
/// ```
///
/// # Panics
/// If the insertion of the packet into the channel within the send method, goes wrong
///
/// # Errors
/// if the result taken from the channel does not return an Ok<[ParsedPacket]>.
///
/// # Remarks
/// Each [Aggregator] runs in a separate thread, so you can create multiple [Parser] sending [ParsedPacket] to multiple [Aggregator]
#[derive(Clone)]
pub struct Aggregator{
    tx: Sender<ParsedPacket>,
    aggregated_data: Arc<Mutex<HashMap<Connection,ConnectionMetadata>>>
}
impl Aggregator{
    ///Creates the [Aggregator] and a thread that receives [ParsedPacket] via channel and inserts them into the [Aggregator] map
    ///
    /// # Examples
    /// Basic usage:
    /// ```rust
    /// use Network_analyzer::aggregator::Aggregator;
    /// use Network_analyzer::parser::Parser;
    ///
    /// let aggregator=Aggregator::new();
    /// ```
    ///# Errors
    /// if the result taken from the channel does not return an Ok<[ParsedPacket]>.
    pub fn new() -> Self {
        let(tx,rx) = channel::<ParsedPacket>();
        //declare an hashmap with key as tuple of (destination_ip,port) and value as tuple of (protocol, size, first_timestamp, last_timestamp)
        let mut aggregated_data = Arc::new(Mutex::new(HashMap::<Connection,ConnectionMetadata>::new()));
        let mut aggregated_data_clone = Arc::clone(&aggregated_data);

        std::thread::spawn( move || {
            println!("Network Analyzer Started\n");
            let mut loop1 = true;
            while loop1 {
                let msg = rx.recv();
                match msg {
                    Err(_) => {
                        //All senders to this channel have been dropped
                        //the thread can die.
                        loop1 = false;
                    },
                    Ok(p) => {
                      //  println!("processing: {:?}", p);

                        let key = Connection::new(p.source_ip, p.destination_ip, p.source_port, p.destination_port, p.protocol);
                        let mut aggregated_map = aggregated_data_clone.lock().unwrap();

                        if aggregated_map.contains_key(&key) {
                         //   println!("Key already exists, updating value");
                            let mut value = aggregated_map.get_mut(&key).unwrap();
                            (*value).size = p.size + (*value).size;
                            (*value).last_timestamp = p.timestamp;
                            //aggregated_map.insert(key,(*value).clone());
                        } else {
                         //   println!("Key does not exist, inserting new value");
                            let value = ConnectionMetadata::new(p.size,p.timestamp.clone(),p.timestamp);
                            aggregated_map.insert(key,value);
                        }

                    }
                }
            }
        });
        Aggregator { tx, aggregated_data }
    }

    ///Allows a [ParsedPacket] to be sent to the aggregator via the [Aggregator] sender
    pub fn send(&self, packet: ParsedPacket){
        self.tx.send(packet).unwrap();
    }

    ///Returns aggregated data from the [Aggregator]
    pub fn get_aggregated_data(&self) -> Arc<Mutex<HashMap<Connection,ConnectionMetadata>>> {
        Arc::clone(&self.aggregated_data)
    }

    ///Returns the [Aggregator] sender to allow it to send [ParsedPacket]
    pub fn get_sender(&self) -> Sender<ParsedPacket> {
        self.tx.clone()
    }
}
