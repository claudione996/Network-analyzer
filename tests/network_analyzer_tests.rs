use std::sync::{Arc, mpsc};
use pcap::{Capture, Device};
//import lib.rs
use Network_analyzer::*;
use Network_analyzer::network_analyzer_components;
use Network_analyzer::network_analyzer_components::aggregator::Aggregator;
//import ParsedPacket
use network_analyzer_components::ParsedPacket::ParsedPacket;
//import parser
use network_analyzer_components::parser::Parser;


#[test]
fn test_aggregator() {
    let timestamp1 : usize = 1667775485;
    let source_ip1 : String = "127.0.0.1".to_string();
    let destination_ip1 : String = "128.0.0.2".to_string();
    let source_port1 : usize = 62911;
    let destination_port1 : usize = 80;
    let protocol1 : String = "TCP".to_string();
    let size1 : usize = 64;
    //declare a list of ParsePacket initialized with dummy values
    let list:Vec<ParsedPacket> = vec![ParsedPacket::new(timestamp1,source_ip1.clone(),destination_ip1.clone(),source_port1,destination_port1,protocol1.clone(),size1),
                    ParsedPacket::new(timestamp1+1,source_ip1.clone(),destination_ip1.clone(),source_port1,destination_port1,protocol1.clone(),size1),
                    ParsedPacket::new(timestamp1+2,source_ip1.clone(),destination_ip1.clone(),source_port1,destination_port1,protocol1.clone(),size1),
                    ParsedPacket::new(timestamp1+3,source_ip1.clone(),destination_ip1.clone(),source_port1,destination_port1,protocol1.clone(),size1)];
    let mut aggregator = Aggregator::new();
    //send each packet to the aggregator
    for packet in list {
        aggregator.send(packet);
    }
    //wait for the aggregator to finish
    std::thread::sleep(std::time::Duration::from_secs(5));
    //test the aggregated data
    let key = ("128.0.0.2".to_string(),80);
    let binding = aggregator.get_aggregated_data();
    let aggregated_data = binding.lock().unwrap();
    assert_eq!(aggregated_data.len(),1);
    assert_eq!(aggregated_data.contains_key(&key),true);
    let value = aggregated_data.get(&key).unwrap();
    //assert_eq!(*value.len(),4);
    assert_eq!(value.0,"TCP".to_string());
    assert_eq!(value.1,256 as usize);
    assert_eq!(value.2,1667775485);
    assert_eq!(value.3,1667775488);
    println!("aggregated record received: {:?}, {:?}",key,value);
}

#[test]
fn test_aggregator_multiple_destinations() {
    //prima entry
    let timestamp1 : usize = 1667775485;
    let source_ip1 : String = "127.0.0.1".to_string();
    let destination_ip1 : String = "128.0.0.2".to_string();
    let source_port1 : usize = 62911;
    let destination_port1 : usize = 80;
    let protocol1 : String = "TCP".to_string();
    let size1 : usize = 64;
    //seconda entry
    let timestamp2 : usize = 1667775470;
    let source_ip2 : String = "127.0.0.3".to_string();
    let destination_ip2 : String = "128.0.0.4".to_string();
    let source_port2 : usize = 62912;
    let destination_port2 : usize = 81;
    let protocol2 : String = "TCP".to_string();
    let size2 : usize = 64;

    let list1:Vec<ParsedPacket> = vec![ParsedPacket::new(timestamp1,source_ip1.clone(),destination_ip1.clone(),source_port1,destination_port1,protocol1.clone(),size1),
                                      ParsedPacket::new(timestamp1+1,source_ip1.clone(),destination_ip1.clone(),source_port1,destination_port1,protocol1.clone(),size1),
                                      ParsedPacket::new(timestamp1+2,source_ip1.clone(),destination_ip1.clone(),source_port1,destination_port1,protocol1.clone(),size1),
                                      ParsedPacket::new(timestamp1+3,source_ip1.clone(),destination_ip1.clone(),source_port1,destination_port1,protocol1.clone(),size1)];

    let list2:Vec<ParsedPacket> = vec![ParsedPacket::new(timestamp2,source_ip2.clone(),destination_ip2.clone(),source_port2,destination_port2,protocol2.clone(),size2),
                                      ParsedPacket::new(timestamp2+1,source_ip2.clone(),destination_ip2.clone(),source_port2,destination_port2,protocol2.clone(),size2)];

    let mut aggregator = Aggregator::new();
    //send each packet to the aggregator
    for packet in list1 {
        aggregator.send(packet);
    }
    for packet in list2 {
        aggregator.send(packet);
    }
    //wait for the aggregator to finish
    std::thread::sleep(std::time::Duration::from_secs(2));
    //test the aggregated data
    //test the aggregated data
    let key1 = ("128.0.0.2".to_string(),80);
    let key2 = ("128.0.0.4".to_string(),81);
    let binding = aggregator.get_aggregated_data();
    let aggregated_data = binding.lock().unwrap();
    assert_eq!(aggregated_data.len(),2);
    assert_eq!(aggregated_data.contains_key(&key1),true);
    assert_eq!(aggregated_data.contains_key(&key2),true);
    let value1 = aggregated_data.get(&key1).unwrap();
    let value2 = aggregated_data.get(&key2).unwrap();
    //assert_eq!(*value.len(),4);
    assert_eq!(value1.0,"TCP".to_string());
    assert_eq!(value1.1,256 as usize);
    assert_eq!(value1.2,1667775485);
    assert_eq!(value1.3,1667775488);

    assert_eq!(value2.0,"TCP".to_string());
    assert_eq!(value2.1,128 as usize);
    assert_eq!(value2.2,1667775470);
    assert_eq!(value2.3,1667775471);
    println!("aggregated record1 received: {:?}, {:?}",key1,value1);
    println!("aggregated record2 received: {:?}, {:?}",key2,value2);


}

#[test]
fn test_parser(){
    println!("test_parser starting");
    //define a channel to send the parsed packet
    let (sender, receiver) = mpsc::channel();
    //create a parser
    println!("before parser declaration");
    let mut _parser = Parser::new("\\Device\\NPF_{CD484432-E2CB-46E8-8FCC-3D919CF3533E}",sender);
    println!("after parser declaration, before waiting 5s");
    //wait for the parser to finish
    std::thread::sleep(std::time::Duration::from_secs(5));
    println!("after waiting 5s");
    //test the parsed packet
    let parsed_packet = receiver.recv().unwrap();
    println!("parsed packet received: {:?}",parsed_packet);

}

#[test]
fn test_parser_with_aggregator(){
    let mut aggregator = Aggregator::new();
    let mut _parser = Parser::new("\\Device\\NPF_{CD484432-E2CB-46E8-8FCC-3D919CF3533E}",aggregator.get_sender());
    //wait for the parser/aggregator to process some packets
    println!("waiting for the parser/aggregator to process some packets");
    std::thread::sleep(std::time::Duration::from_secs(5));
    //print the aggregated data
    let binding = aggregator.get_aggregated_data();
    let aggregated_data = binding.lock().unwrap();
    for (key,value) in aggregated_data.iter() {
        println!("aggregated record received: {:?}, {:?}",key,value);
    }

}













