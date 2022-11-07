use std::collections::HashMap;
use crate::network_analyzer_components::aggregator::Aggregator;
use crate::network_analyzer_components::parser::Parser;

pub struct SocketListener{
    parser: Parser,
    aggregator:Aggregator
}

impl SocketListener {
    pub fn new(device:&str) -> Self {
        let agg=Aggregator::new();
        let aggregator_tx=agg.get_sender();
        let parser=Parser::new(device, aggregator_tx);
        SocketListener{parser,aggregator:agg}
    }

    pub fn pause(&self){
        drop(&self.parser);
        let data=self.aggregator.get_aggregated_data();
        let data=data.lock().unwrap();
        println!("{:?}",data);
    }
}
