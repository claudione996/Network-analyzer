use std::sync::Arc;
//import lib.rs
use Network_analyzer::*;
use Network_analyzer::network_analyzer_components;
use Network_analyzer::network_analyzer_components::aggregator::Aggregator;
//import ParsedPacket
use network_analyzer_components::ParsedPacket::ParsedPacket;


#[test]
fn test_aggregator() {
    //declare a list of ParsePacket initialized with dummy values
    let list:Vec<ParsedPacket> = vec![ParsedPacket::new(1667775485,"127.0.0.1".to_string(),"128.0.0.2".to_string(),62911,80,"TCP".to_string(),64),
                    ParsedPacket::new(1667775486,"127.0.0.1".to_string(),"128.0.0.2".to_string(),62911,80,"TCP".to_string(),64),
                    ParsedPacket::new(1667775487,"127.0.0.1".to_string(),"128.0.0.2".to_string(),62911,80,"TCP".to_string(),64),
                    ParsedPacket::new(1667775488,"127.0.0.1".to_string(),"128.0.0.2".to_string(),62911,80,"TCP".to_string(),64)];
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
