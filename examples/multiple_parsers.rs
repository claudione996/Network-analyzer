use network_analyzer::select_device;
use std::sync::mpsc::channel;
use network_analyzer::parser::Parser;


fn main() {
    //I am creating a channel where the parser will send the parsed packets
    let (tx, rx) = channel();
    //select the first device from all the network devices of the pc
    println!("Select the first device to sniff:");
    let first_device_name = select_device();
    //select the second device from all the network devices of the pc
    println!("Select the second device to sniff:");
    let second_device_name = select_device();
    //I create the parsers listening to the devices and both sending the parsed packets to the channel i just created
    let _parser1 = Parser::new(&first_device_name, tx.clone());
    let _parser2 = Parser::new(&second_device_name, tx.clone());
    //Now I can use rx to receive the parsed packets from all the parsers
    while let Ok(parsed_packet) = rx.recv() {
        println!("Received packet: {:?}", parsed_packet);
    }

}