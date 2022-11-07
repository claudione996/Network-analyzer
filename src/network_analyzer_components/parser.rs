use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{channel, Sender};
use pcap::{Active, Capture, Packet};
use crate::{parse_packet, ParsedPacket};

/// Struct that receives pcap Packets from a channel, parses them into ParsedPackets and sends them through another channel
#[derive(Clone)]
pub struct Parser{
    parser_tx: Sender<Packet<'static>>
}
impl Parser{
    /// Creates a new Parser that receives pcap Packets through a channel and forwards ParsedPackets to the given Sender
    /// # Arguments
    /// * `aggregator_tx` - The Sender to forward the parsed packets to, is intended to correspond to a Receiver in an Aggregator
    pub fn new(aggregator_tx: Sender<ParsedPacket>) -> Parser {

        let(parser_tx,rx) = channel::<Packet>();

        std::thread::spawn( move || {

            println!("Parser thread started");

            let mut loop1 = true;
            while loop1 {
                let msg = rx.recv();
                match msg {
                    Err(e) => {
                        println!("Error: {}", e);
                        loop1 = false;
                    },
                    Ok(p) => {
                        let parsed=parse_packet(p);
                        match parsed {
                            None => {}
                            Some(x) => {
                                println!("Sending packet {:?} to aggregator", x);
                                aggregator_tx.send(x).unwrap();}
                        }
                    }
                }
            }

        });
        Parser { parser_tx }
    }

    /// Sends a pcap Packet to the Parser
    /// # Arguments
    /// * `packet` - The pcap Packet to be parsed
    pub fn send(&self, packet: Packet){
        self.parser_tx.send(packet).unwrap();
    }
    //pub fn get_sender(&self) -> Sender<Packet<'static>> {
    //    self.parser_tx.clone()
    //}

}
