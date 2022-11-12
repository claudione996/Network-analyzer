use std::sync::{Arc, Condvar, Mutex};
use std::sync::mpsc::{Sender};
use pcap::{Capture};
use crate::modules::lib::parse_packet;
use crate::modules::parsedpacket::ParsedPacket;

/// Struct that receives pcap Packets from a channel, parses them into ParsedPackets and sends them through another channel

pub struct Parser{
    stopped:Arc<Mutex<bool>>,
    cv:Arc<Condvar>
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
        let cv=Arc::new(Condvar::new());
        let cv1=cv.clone();

        std::thread::spawn( move || {
            println!("Parser thread started");
            loop {
                    match cap.next_packet() {
                        Ok(packet) => {
                            let mut stopped =stopped.lock().unwrap();
                            println!("t1");
                            let stopped = cv.wait_while(stopped, |x| *x).unwrap();
                            println!("t2");
                            //if *stopped {println!("parser stopped");break}
                            let p=parse_packet(packet);
                            match p {
                                None => {println!("package not valid for parsing (not IP/TCP or IP/UDP)");},
                                Some(x) => {aggregator_tx.send(x).unwrap();}
                            } },
                        Err(_) => {println!("Packet Error");break}
                    }
            }
        });
        Parser{stopped:a,cv:cv1}
    }

    pub fn stop_iter_cap(&self){
        println!("stop1");
        let mut stopped =self.stopped.lock().unwrap();
        println!("stop2");
        *stopped=true;
    }

    pub fn resume_iter_cap(&self){
        println!("resume1");
        let mut stopped =self.stopped.lock().unwrap();
        println!("resume2");
        *stopped=false;
        self.cv.notify_one();
    }

}
