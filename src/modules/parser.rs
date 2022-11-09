use std::sync::{Arc, Mutex};
use std::sync::mpsc::{Sender};
use pcap::{Capture};
use crate::modules::lib::parse_packet;
use crate::modules::parsedpacket::ParsedPacket;

/// Struct that receives pcap Packets from a channel, parses them into ParsedPackets and sends them through another channel

pub struct Parser{
    stopped:Arc<Mutex<bool>>
}
impl Parser{
    /// Creates a new Parser that receives pcap Packets through a channel and forwards ParsedPackets to the given Sender
    /// # Arguments
    /// * `aggregator_tx` - The Sender to forward the parsed packets to, is intended to correspond to a Receiver in an Aggregator
    pub fn new(device: &str, aggregator_tx: Sender<ParsedPacket>) -> Parser {

        let mut cap = Capture::from_device(device).unwrap()
            .promisc(true)
            .open().expect("Failed to open device");

        let a=Arc::new(Mutex::new(false));
        let stopped=a.clone();

        std::thread::spawn( move || {

            println!("Parser thread started");

            loop {

                {
                    let mut stopped =stopped.lock().unwrap();
                    if *stopped {println!("parser stopped");break}

                    println!("prova");

                    match cap.next_packet() {
                        Ok(packet) => { let p=parse_packet(packet);
                            match p {
                                None => {println!("Error parsing packet");},
                                Some(x) => {aggregator_tx.send(x).unwrap();}
                            } },
                        Err(_) => {break}
                    }

                }

            }

        });
        Parser{stopped:a}
    }

    pub fn drop_cap(&self){
        //println!("1");
        let mut stopped =self.stopped.lock().unwrap();
        //println!("2");
        *stopped=true;
    }

}
