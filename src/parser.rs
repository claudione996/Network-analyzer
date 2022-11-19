use std::sync::{Arc, Condvar, Mutex};
use std::sync::mpsc::{Sender};
use chrono::{DateTime, NaiveDateTime, Utc};
use etherparse::{Icmpv4Type, Icmpv6Type, IpHeader, PacketHeaders, TransportHeader};
use etherparse::IpHeader::{Version4, Version6};
use etherparse::TransportHeader::{Icmpv4, Icmpv6, Tcp, Udp};
use pcap::{Capture, Packet};
use crate::parsed_packet::ParsedPacket;

/// Struct that parses pcap Packets into [ParsedPacket] from a network device and sends them through another channel
///
/// # Examples
/// Basic usage:
/// ```rust
/// use std::sync::mpsc::{channel, Sender};
/// use Network_analyzer::parser::Parser;
/// // i am creating a channel where the parser will send the parsed packets
/// let (tx, rx) = channel();
/// // i create a new parser listening to device "eth0" and sending the parsed packets to the channel i just created
/// let parser = Parser::new("eth0", tx); ///
/// // now i can use rx to receive the parsed packets from all the parsers
/// // notice that the parser is running in a separate thread, so i can wait for the packets in the main thread
/// while let Ok(parsed_packet) = rx.recv() {
///    println!("Received packet: {:?}", parsed_packet);
/// }
/// ```
///
/// Advanced usage: create multiple parsers listening to multiple devices
/// ```rust
/// use std::sync::mpsc::{channel, Sender};
/// use Network_analyzer::parser::Parser;
/// // i am creating a channel where the parser will send the parsed packets
/// let (tx, rx) = channel();
/// // i create a new parser listening to device "eth0" and sending the parsed packets to the channel i just created
/// let parser1 = Parser::new("eth0", tx.clone());
/// let parser2 = Parser::new("eth1", tx.clone());
///
/// // now i can use rx to receive the parsed packets from all the parsers
/// while let Ok(parsed_packet) = rx.recv() {
///    println!("Received packet: {:?}", parsed_packet);
/// }
/// ```
///
/// # Panics
/// TODO: add panic description
///
/// # Errors
/// TODO: add error description
///
/// # Remarks
/// Each parser runs in a separate thread, so you can create multiple parsers listening to multiple devices
///
pub struct Parser{
    stopped:Arc<Mutex<bool>>,
    cv:Arc<Condvar>
}
impl Parser{
    /// Creates a new Parser that receives pcap Packets through a channel and forwards ParsedPackets to the given Sender
    /// # Arguments
    /// * `aggregator_tx` - The Sender to forward the parsed packets to, is intended to correspond to a Receiver in an Aggregator
    /// * `device` - The name of device to listen to
    /// # Example
    /// Basic usage:
    /// ```rust
    /// use std::sync::mpsc::{channel, Sender};
    /// use Network_analyzer::parser::Parser;
    /// // i am creating a channel where the parser will send the parsed packets
    /// let (tx, rx) = channel();
    /// // i create a new parser listening to device "eth0" and sending the parsed packets to the channel i just created
    /// let parser = Parser::new("eth0", tx);
    /// ```
    /// # Panics
    /// Panics if it fails to open the device with the given name
    /// # Remarks
    /// This function spawns a new thread that will run forever until the Parser is stopped with the `stop_iter_cap()` function
    /// or is dropped
    pub fn new(device: &str, aggregator_tx: Sender<ParsedPacket>) -> Parser {

        let mut cap = Capture::from_device(device).unwrap()
            .promisc(true)
            .open().expect("Failed to open device");

        let a=Arc::new(Mutex::new(false));
        let stopped=a.clone();
        let cv=Arc::new(Condvar::new());
        let cv1=cv.clone();

        // TODO: add a way to stop the thread (not only pausing it). Maybe a channel that sends a message to the thread to stop it like in the report_writer
        std::thread::spawn( move || {
            println!("Parser thread started");
            loop {
                    match cap.next_packet() {
                        Ok(packet) => {
                            let mut stopped =stopped.lock().unwrap();
                            let stopped = cv.wait_while(stopped, |x| *x).unwrap();
                            let p= Parser::parse_packet(packet);
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

    /// Pauses the parser from receiving packets if it is not already paused
    pub fn stop_iter_cap(&self){
        let mut stopped =self.stopped.lock().unwrap();
        *stopped=true;
    }

    /// Resumes the parser from receiving packets if it was paused, otherwise does nothing
    pub fn resume_iter_cap(&self){
        let mut stopped =self.stopped.lock().unwrap();
        *stopped=false;
        self.cv.notify_one();
    }

    /// Parses a pcap Packet into a ParsedPacket
    fn parse_packet(packet:Packet) -> Option<ParsedPacket> {
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
                //println!("V4");
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
                //println!("IP VERSION 6");
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

}
