use std::fs::File;
use std::io;
use std::num::ParseIntError;
use pcap::{Active, Capture, Device, Packet};

pub mod aggregator;
pub mod parsed_packet;
pub mod parser;
pub mod socket_listener;
pub mod analyzer;
pub mod report_writer;
pub mod report_entry;

//used only for debugging
pub fn select_debug() -> Capture<Active> {
    let cap = Capture::from_device("\\Device\\NPF_{DFADCF5E-E518-4EB5-A225-3126223CB9A2}").unwrap()
        .promisc(true)
        .open().unwrap();
    return cap;
}

pub fn select_default() -> Capture<Active> {
    let main_device = Device::lookup().expect("lookup error").expect("No default device found");
    let cap = Capture::from_device(main_device).unwrap()
        .promisc(true)
        .open().unwrap();
    return cap;
}

pub fn select_device() -> String {
    // list all of the devices pcap tells us are available
    let dev_list= Device::list().expect("device lookup failed");
    let number:usize;

    let mut i=0;
    for device in &dev_list {
        i+=1;
        match device.desc.as_ref() {
            None => println!("{})  {:?}", i, device.name),
            Some(x) => println!("{})  {:?}", i, x)
        }
    }
    loop{
        let mut input_line = String::new();
        io::stdin()
            .read_line(&mut input_line)
            .expect("Failed to read line");
        let number_res:Result<usize, ParseIntError> = input_line.trim().parse();
        match number_res{
            Ok(x) => {
                if x > 0 && x <= i {
                    number = x-1;
                    break;
                }
                else{
                    println!("Device number must be in the interval 1-{i} \nSelect a correct device to sniff:");
                }},
            Err(_) => {println!("Device must be a number! \nSelect device in the interval 1-{i}")}
        }

    }

    let device = dev_list[number].clone();
    match device.desc.as_ref(){
        None => {println!("Device selected: {:?}",device.name);
        }
        Some(x) => {println!("Device selected: {:?}",x);
        }
    }
    return device.name;
}

/*TODO: decide if this function is needed and if yes, where to put it
pub fn print_packets(mut cap:Capture<Active>){
    while let Ok(packet) = cap.next_packet() {
        let p=parse_packet(packet);
        match p {
            None => {}
            Some(x) => {println!("{:?}",x);}
        }
    }
}
*/

