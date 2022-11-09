use std::sync::{Arc, Condvar, Mutex};
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
            let cv=Condvar::new();

            println!("Parser thread started");

            loop {

                    match cap.next_packet() {
                        Ok(packet) => {

                            let mut stopped =stopped.lock().unwrap();
                            println!("t1");
                            let stopped = cv.wait_while(stopped, |x| *x).unwrap();
                            println!("t2");

                            if *stopped {println!("parser stopped");break}


                            let p=parse_packet(packet);
                            match p {
                                None => {println!("Error parsing packet");},
                                Some(x) => {aggregator_tx.send(x).unwrap();}
                            } },
                        Err(_) => {break}
                    }

            }

        });
        Parser{stopped:a}
    }

    pub fn stop_iter_cap(&self){
        println!("p1");
        let mut stopped =self.stopped.lock().unwrap();
        println!("p2");
        *stopped=true;
    }



}
