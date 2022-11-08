use std::collections::HashMap;
use std::sync::mpsc::Sender;
use crate::modules::aggregator::Aggregator;
use crate::modules::parser::Parser;


pub struct SocketListener{
    parser: Parser,
    aggregator:Aggregator,
    device:String,
}

impl SocketListener {
    pub fn new(device_str:&str) -> Self {
        let aggregator=Aggregator::new();
        let aggregator_tx=aggregator.get_sender();
        let parser=Parser::new(device_str, aggregator_tx.clone());
        let device=String::from(device_str);
        SocketListener{parser,aggregator,device}
    }

    pub fn pause(&self){
        drop(&self.parser);
        let data=self.aggregator.get_aggregated_data();
        let data=data.lock().unwrap();
        println!("{:?}",data);
    }

    pub fn resume(&mut self){
        let aggregator_tx=self.aggregator.get_sender().clone();
        self.parser=Parser::new(self.device.as_str(), aggregator_tx);
    }
}
