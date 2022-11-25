use std::{io, num::ParseIntError};
use Network_analyzer::analyzer::Analyzer;
use Network_analyzer::select_device;
use std::sync::mpsc::{channel, Sender};
use Network_analyzer::parser::Parser;

fn main() {
    // I am creating a channel where the parser will send the parsed packets
    let (tx, rx) = channel();

    //select the device from all the network devices of the pc
    println!("Select the device to sniff:");
    let device_name = select_device();

    // I create a new parser listening to the selected device and sending the parsed packets to the channel i just created
    let _parser = Parser::new(&device_name, tx);

    /* Now I can use rx to receive the parsed packets from all the parsers
     notice that the parser is running in a separate thread, so i can wait for the packets in the main thread.
      You might wat to open a browser and/or refresh an internet page to see some traffic*/
    while let Ok(parsed_packet) = rx.recv() {
        println!("Received packet: {:?}", parsed_packet);
    }
}