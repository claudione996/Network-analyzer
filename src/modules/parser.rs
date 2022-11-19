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
                            let stopped = cv.wait_while(stopped, |x| *x).unwrap();
                            let p=parse_packet(packet);
                            match p {
                                None => println!("packet not valid for parsing (neither IP/TCP, IP/UDP or IP/ICMP)"),
                                Some(x) => aggregator_tx.send(x).unwrap(),
                            } },
                        Err(_) => {println!("Packet Error"); break }
                    }
            }
        });
        Parser{stopped:a,cv:cv1}
    }

    pub fn stop_iter_cap(&self){
        let mut stopped =self.stopped.lock().unwrap();
        *stopped=true;
    }

    pub fn resume_iter_cap(&self){
        let mut stopped =self.stopped.lock().unwrap();
        *stopped=false;
        self.cv.notify_one();
    }

}
