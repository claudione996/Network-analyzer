use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use crate::modules::analyzer::Analyzer;
use crate::modules::lib::write_report;
use crate::modules::socketlistener::SocketListener;

mod modules;

fn main() {

    let a=Analyzer::new("en0", "report", 5);

}
