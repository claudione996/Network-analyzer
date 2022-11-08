use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use crate::modules::analizer::Analizer;
use crate::modules::lib::write_report;
use crate::modules::socketlistener::SocketListener;

mod modules;

fn main() {
    /*let mut hm =HashMap::<(String, usize),(String, usize, usize, usize)>::new();
    hm.insert((String::from("ciao"),0),(String::from("Rust"),1,2,3));
    let h = Arc::new(Mutex::new(hm));

    write_report("prova_report",h);
    */

    let a=Analizer::new("\\Device\\NPF_{DFADCF5E-E518-4EB5-A225-3126223CB9A2}", "report", 10);


}
