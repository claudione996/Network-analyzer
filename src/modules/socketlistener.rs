use crate::modules::aggregator::Aggregator;
use crate::modules::lib::write_report;
use crate::modules::parser::Parser;

pub struct SocketListener{
    parser: Parser,
    aggregator:Aggregator,
    device:String,
    filename:String,
}

impl SocketListener {
    pub fn new(device_str:&str,filename:&str) -> Self {
        let aggregator=Aggregator::new();
        let aggregator_tx=aggregator.get_sender();
        let parser=Parser::new(device_str, aggregator_tx.clone());

        //parser.drop_cap();

        let device=String::from(device_str);
        let filename=String::from(filename);
        SocketListener{parser,aggregator,device,filename}
    }

    pub fn pause(&self){
    self.parser.stop_iter_cap();
    }

    pub fn resume(&mut self){

    }

    pub fn stop(&self){
        write_report(self.filename.as_str(), self.aggregator.get_aggregated_data());
    }
}
