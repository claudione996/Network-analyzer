use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use crate::modules::lib::write_report;
use crate::modules::socketlistener::SocketListener;

mod modules;

fn main() {
    let device = "en0";
    let sock=SocketListener::new(device);
   /* std::thread::sleep(std::time::Duration::from_secs(5));
    println!("pause");
    sock.pause();
    println!("resume");
    std::thread::sleep(std::time::Duration::from_secs(5));
    println!("pause");
    sock.pause();*/
    let mut hm =HashMap::<(String, usize),(String, usize, usize, usize)>::new();
    hm.insert((String::from("ciao"),0),(String::from("Rust"),1,2,3));
    let h = Arc::new(Mutex::new(hm));

    write_report("prova_report",h);

}
