use std::io;
use etherparse::{IpHeader, PacketHeaders, TransportHeader};
use etherparse::IpHeader::Version4;
use pcap::{Active, Capture, Device, Packet};
use crate::network_analyzer_components::looper::Looper;
use crate::network_analyzer_components::ParsedPacket::ParsedPacket;
mod network_analyzer_components;

pub fn select_debug() -> Capture<Active> {
    let mut cap = Capture::from_device("\\Device\\NPF_{DFADCF5E-E518-4EB5-A225-3126223CB9A2}").unwrap()
        .promisc(true)
        .open().unwrap();
    return cap;
}

pub fn select_default() -> Capture<Active> {
    let main_device = Device::lookup().expect("lookup error").expect("No default device found");
    let mut cap = Capture::from_device(main_device).unwrap()
        .promisc(true)
        .open().unwrap();
    return cap;
}

pub fn select_device() -> Capture<Active> {
    let mut i=0;
    // list all of the devices pcap tells us are available
    let dev_list= Device::list().expect("device lookup failed");
    for device in &dev_list {
        i+=1;
        println!("{})  {:?}",i, device.desc.as_ref().unwrap());
    }
    let mut input_line = String::new();
    io::stdin()
        .read_line(&mut input_line)
        .expect("Failed to read line");
    let mut number: usize = input_line.trim().parse().expect("Input not an integer");
    number-=1;
    let device = dev_list[number].clone();
    println!("Selected {:?}",device.desc.as_ref().unwrap());
    let mut cap = Capture::from_device(device).unwrap()
        .promisc(true)
        .open().unwrap();
    return cap;
}

pub fn parse_packet(packet:Packet) -> Option<ParsedPacket> {
    let ph=PacketHeaders::from_ethernet_slice(&packet).unwrap();
    let mut source=String::new();
    let mut destination=String::new();
    let mut weight = 0;
    let mut ts=0;
    let mut trs_protocol =String::new();
    let mut src_port =0;
    let mut dest_port =0;
    let mut show=true;

    match ph.ip {
        Some(x)=> match x {
            Version4(h,e)=> {
                let mut s=h.source.into_iter().map(|i| i.to_string() + ".").collect::<String>();
                s.pop();
                source=s;

                let mut d=h.destination.into_iter().map(|i| i.to_string() + ".").collect::<String>();
                d.pop();
                destination=d;

                weight=packet.header.len as usize;
                ts=packet.header.ts.tv_sec as usize;
            },
            _ => {}
        },
        None => {}
    }
    match  ph.transport {
        Some(x)=> match x {
            TransportHeader::Udp(y) => {trs_protocol=String::from("Udp");src_port=y.source_port as usize;dest_port=y.destination_port as usize}
            TransportHeader::Tcp(y) => {trs_protocol=String::from("Tcp");src_port=y.source_port as usize;dest_port=y.destination_port as usize}
            _ => {show=false}
        },
        _ => {}
    }
    if show
    {
        let parsed_p= ParsedPacket::new(ts, source, destination, src_port, dest_port, trs_protocol, weight);
        //println!("{:?}", parsed_p);
        return Some(parsed_p);
    }
    None
}

pub fn print_packets(mut cap:Capture<Active>){
    while let Ok(packet) = cap.next_packet() {
        let p=parse_packet(packet);
        match p {
            None => {}
            Some(x) => {println!("{:?}",x);}
        }
    }
}

/// only the print function is executed in the background, the capture is still blocking
pub fn print_packets_background(mut cap:Capture<Active>){
    let mut looper = Looper::new(|p| println!("received packet! {}",p),|| println!("CLEANUP() CALLED"));
    while let Ok(packet) = cap.next_packet() {
        let p_str = format!("{:?}",packet);
        looper.send(p_str);
    }
}

/*
pub fn parse_packet(packet: &pcap::Packet) -> ParsedPacket {
    let timestamp = packet.header.ts.tv_sec;
    //let source_ip = packet.header.ts.tv_sec;
    //let destination_ip = packet.header.ts.tv_sec;
    //let source_port = packet.header.ts.tv_sec;
    //let destination_port = packet.header.ts.tv_sec;
    //let protocol = packet.header.ts.tv_sec;
    let length = packet.header.ts.tv_sec;
    //let info = packet.header.ts.tv_sec;
    let parsed_packet = ParsedPacket::new(timestamp,source_ip,destination_ip,source_port,destination_port,protocol,length,info);
    return parsed_packet;
}
*/