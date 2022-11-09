use std::io;
use crate::modules::socketlistener::SocketListener;

pub struct Analyzer{
    pub sl: SocketListener,
}

impl Analyzer{
    pub fn new(device:&str,filename:&str,timer:u64)->Self{
        let sl=SocketListener::new(device,filename);
        //std::thread::sleep(std::time::Duration::from_secs(timer));
        //sl.stop();
        Analyzer{sl}
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
            1 => {println!("choice 1"); self.sl.pause() },
            2 => {println!("choice 2"); self.sl.resume()}
            _ => {}
        }

        }
        //std::thread::sleep(std::time::Duration::from_secs(10));

    }
}