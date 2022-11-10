use std::io;
use crate::modules::report_writer::ReportWriter;
use crate::modules::socketlistener::SocketListener;

pub struct Analyzer{
    pub sl: SocketListener,
    pub report_writer: ReportWriter,
}

impl Analyzer{
    pub fn new(device:&str,filename:&str,timer:u64)->Self{
        let sl=SocketListener::new(device);
        let report_writer = ReportWriter::new(filename.to_string(), timer, sl.get_aggregated_data());
        Analyzer{sl,report_writer}
    }

    pub fn choice_loop(&self){
        loop {
        println!("select 1 or 2");
        let mut input_line = String::new();
        io::stdin()
            .read_line(&mut input_line)
            .expect("Failed to read line");
        let mut number: usize = input_line.trim().parse().expect("Input not an integer");

        match number{
            1 => {println!("choice 1: pausing SocketListener and report writer"); self.sl.pause(); self.report_writer.pause();},
            2 => {println!("choice 2: resuming SocketListener and report writer"); self.sl.resume(); self.report_writer.resume();}
            _ => {println!("invalid input: select either 1 (to pause) or 2 (to resume)");},
        }

        }
        //std::thread::sleep(std::time::Duration::from_secs(10));

    }

    pub fn pause(&self){
        println!("choice 1: pausing SocketListener and report writer");
        self.sl.pause();
        self.report_writer.pause();
    }

    pub fn resume(&self){
        println!("choice 2: resuming SocketListener and report writer");
        self.sl.resume();
        self.report_writer.resume();
    }

    pub fn exit(&self){
        //TODO: implement exit also for SocketListener and its submodules (parser and aggregator)
        // such that they can be stopped gracefully (thread exits from the loop)
        self.sl.pause();
        self.report_writer.exit();
    }
}