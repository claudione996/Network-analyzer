use std::collections::HashMap;
use std::sync::mpsc::Sender;
use crate::network_analyzer_components::aggregator::Aggregator;
use crate::network_analyzer_components::ParsedPacket::ParsedPacket;
use crate::network_analyzer_components::parser::Parser;

pub struct SocketListener{
    parser: Parser,
    aggregator:Aggregator,
    device:String,
    aggregator_tx:Sender<ParsedPacket>

}

impl SocketListener {
    pub fn new(device_str:&str) -> Self {
        let aggregator=Aggregator::new();
        let aggregator_tx=aggregator.get_sender();
        let parser=Parser::new(device_str, aggregator_tx.clone());
        let device=String::from(device_str);
        SocketListener{parser,aggregator,device,aggregator_tx}
    }

    pub fn pause(&self){
        drop(&self.parser);
        let data=self.aggregator.get_aggregated_data();
        let data=data.lock().unwrap();
        println!("{:?}",data);
    }

    pub fn resume(&mut self){
        self.parser=Parser::new(self.device.as_str(), self.aggregator_tx.clone());
    }
}
