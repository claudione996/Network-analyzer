use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{channel, Sender};
use pcap::{Active, Capture, Packet};
use crate::modules::lib::parse_packet;
use crate::modules::parsedpacket::ParsedPacket;

/// Struct that receives pcap Packets from a channel, parses them into ParsedPackets and sends them through another channel
#[derive(Clone)]
pub struct Parser{
}
impl Parser{
    /// Creates a new Parser that receives pcap Packets through a channel and forwards ParsedPackets to the given Sender
    /// # Arguments
    /// * `aggregator_tx` - The Sender to forward the parsed packets to, is intended to correspond to a Receiver in an Aggregator
    pub fn new(device: &str, aggregator_tx: Sender<ParsedPacket>) -> Parser {

        let mut cap = Capture::from_device(device).unwrap()
            .promisc(true)
            .open().expect("Failed to open device");

        std::thread::spawn( move || {

            println!("Parser thread started");

            while let Ok(packet) = cap.next_packet() {
                let p=parse_packet(packet);
                match p {
                    None => {println!("Error parsing packet");},
                    Some(x) => {aggregator_tx.send(x).unwrap();}
                }
            }

        });
        Parser { }
    }

}
