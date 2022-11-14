use std::fs::File;
use std::num::ParseIntError;
use std::{fs, io};
use std::collections::HashMap;
use std::fmt::format;
use std::io::{BufWriter, Write};
use std::sync::{Arc, Mutex};
use chrono::{DateTime, NaiveDateTime, Utc};
use chrono::format::{DelayedFormat, StrftimeItems};
use etherparse::{Icmpv4Type, Icmpv6Type, IpHeader, PacketHeaders, TransportHeader};
use etherparse::IpHeader::{Version4, Version6};
use etherparse::TransportHeader::{Icmpv4, Icmpv6, Tcp, Udp};
use pcap::{Active, Capture, Device, Packet};
use crate::modules::aggregator::Aggregator;
use crate::modules::parsedpacket::ParsedPacket;
use crate::modules::report_entry::{Connection, ConnectionMetadata};


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
    let dev_list= pcap::Device::list().expect("device lookup failed");
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
            Err(_) => {println!("Device must be a number")}
        }

    }

    let device = dev_list[number].clone();
    match device.desc.as_ref(){
        None => {    println!("Device selected: {:?}",device.name);
        }
        Some(x) => {    println!("Device selected: {:?}",x);
        }
    }
    return device.name;
}

pub fn parse_packet(packet:Packet) -> Option<ParsedPacket> {
    let ph=PacketHeaders::from_ethernet_slice(&packet).unwrap();
    let mut source=String::new();
    let mut destination=String::new();
    let mut size = 0;
    let mut ts= String::new();
    let mut trs_protocol = String::new();
    let mut src_port = None;
    let mut dest_port = None;
    let mut show= true;
    match ph.ip {
        Some(Version4(h, _)) =>{
            println!("V4");
            let mut s=h.source.into_iter().map(|i| i.to_string() + ".").collect::<String>();
            s.pop();
            source=s;
            let mut d=h.destination.into_iter().map(|i| i.to_string() + ".").collect::<String>();
            d.pop();
            destination=d;
            size=packet.header.len as usize;
            let time_number=packet.header.ts.tv_sec as i64;
            let nt = NaiveDateTime::from_timestamp(time_number, 0);
            let dt: DateTime<Utc> = DateTime::from_utc(nt, Utc);
            ts = dt.format("%Y-%m-%d %H:%M:%S").to_string();
        },
        Some(Version6(h, _)) => {
            println!("IP VERSION 6");
            let mut s=h.source.into_iter().map(|i| i.to_string() + ".").collect::<String>();
            s.pop();
            source=s;
            let mut d=h.destination.into_iter().map(|i| i.to_string() + ".").collect::<String>();
            d.pop();
            destination=d;
            size=packet.header.len as usize;
            let time_number=packet.header.ts.tv_sec as i64;
            let nt = NaiveDateTime::from_timestamp(time_number, 0);
            let dt: DateTime<Utc> = DateTime::from_utc(nt, Utc);
            ts = dt.format("%Y-%m-%d %H:%M:%S").to_string();
        },
        None => {//TODO: decide what to do with packets without IP header
        }
    }
    match  ph.transport {
        Some(Tcp(th))=> {
            trs_protocol = String::from("TCP");
            src_port = Some(th.source_port as usize);
            dest_port = Some(th.destination_port as usize);
        },
        Some(Udp(th)) => {
            trs_protocol = String::from("UDP");
            src_port = Some(th.source_port as usize);
            dest_port = Some(th.destination_port as usize);
        },
        Some(Icmpv4(th)) => trs_protocol = match th.icmp_type {
            Icmpv4Type::Unknown { .. } => String::from("ICMPv4: Type Unknown"),
            Icmpv4Type::DestinationUnreachable(_) => String::from("ICMPv4: Destination Unreachable"),
            Icmpv4Type::Redirect(_) => String::from("ICMPv4: Redirect"),
            Icmpv4Type::TimeExceeded(_) => String::from("ICMPv4: Time Exceeded"),
            Icmpv4Type::ParameterProblem(_) => String::from("ICMPv4: Parameter Problem"),
            Icmpv4Type::TimestampRequest(_) => String::from("ICMPv4: Timestamp Request"),
            Icmpv4Type::TimestampReply(_) => String::from("ICMPv4: Timestamp Reply"),
            Icmpv4Type::EchoReply(_) => String::from("ICMPv4: Echo Reply"),
            Icmpv4Type::EchoRequest(_) => String::from("ICMPv4: Echo Request"),
        },
        Some(Icmpv6(th)) => trs_protocol = match th.icmp_type {
            Icmpv6Type::Unknown { .. } => String::from("ICMPv6: Type Unknown"),
            Icmpv6Type::DestinationUnreachable(_) => String::from("ICMPv6: Destination Unreachable"),
            Icmpv6Type::PacketTooBig { .. } => String::from("ICMPv6: Packet Too Big"),
            Icmpv6Type::TimeExceeded(_) => String::from("ICMPv6: Time Exceeded"),
            Icmpv6Type::ParameterProblem(_) => String::from("ICMPv6: Parameter Problem"),
            Icmpv6Type::EchoRequest(_) => String::from("ICMPv6: Echo Request"),
            Icmpv6Type::EchoReply(_) => String::from("ICMPv6: Echo Reply"),
        },
        None => {//TODO: decide how to handle this case
            show = false;
        }
    }
    if show
    {
        let parsed_p= ParsedPacket::new(ts, source, destination, src_port, dest_port, trs_protocol, size);
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

//used only for debugging
pub fn send_to_aggregator(mut cap:Capture<Active>){
    let agg=Aggregator::new();

    while let Ok(packet) = cap.next_packet() {
        let p=parse_packet(packet);
        match p {
            None => {}
            Some(x) => {agg.send(x)}
        }
    }
}

pub fn create_dir_report(filename:&str) -> BufWriter<File> {
    let res_dir=fs::create_dir("report");
    //TODO: handle error or success
    match res_dir {
        Ok(_) => {}
        Err(_) => {}
    }
    let mut path =String::from("report/");
    path.push_str(filename);
    path.push_str(".txt");
    println!("{path}");
    let input=File::create(path.as_str()).expect("Error creating output file\n\r");
    let output = BufWriter::new(input);
    return output;

}
//, aggregated_data: Arc<Mutex<HashMap<(String,usize),(String,usize,usize,usize)>>>
pub fn write_report(filename:&str,aggregated_data: Arc<Mutex<HashMap<Connection, ConnectionMetadata>>>){
   let aggregated_data=aggregated_data.lock().unwrap();

    let mut output =create_dir_report(filename);
    writeln!(output, "|   Src IP address  |  Dst IP address   |  Src port |  Dst port |  Protocol |    Bytes      |  Initial timestamp    |   Final timestamp  |").expect("Error writing output file\n\r");
    writeln!(output, "| :---------------: | :---------------: | :-------: | :-------: | :-------: | :-----------: | :-------------------: | :----------------: |").expect("Error writing output file\n\r");

    for (conn,data) in aggregated_data.iter(){
        let port_src = match conn.source_port {
            Some(x) => x.to_string(),
            None => String::from("-"),
        };
        let port_dst = match conn.destination_port {
            Some(x) => x.to_string(),
            None => String::from("-"),
        };
        let bytes= data.size.to_string();
        //                  ip_src,     ip_dst,     port_src,   port_dst,  protocol,   bytes, first_timestamp,last_timestamp
        writeln!(output, "| {0:<15} \t| {1:<15} \t| {2:<5} \t | {3:<5} \t| {4:<7} \t| {5:<9} \t| {6:<15} \t| {7:<3}| ",conn.source_ip,conn.destination_ip,port_src,port_dst,conn.protocol,bytes,data.first_timestamp,data.last_timestamp).expect("Error writing output file\n\r");
    }


}