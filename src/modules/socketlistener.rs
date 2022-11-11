use crate::modules::aggregator::Aggregator;
use crate::modules::lib::write_report;
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
    self.parser.stop_iter_cap();
    }

    pub fn resume(&self){
    self.parser.resume_iter_cap();
    }

    pub fn get_aggregated_data(&self)->std::sync::Arc<std::sync::Mutex<std::collections::HashMap<(String, usize),(String, usize, String, String)>>>{
        self.aggregator.get_aggregated_data()
    }

}
