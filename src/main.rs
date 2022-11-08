use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use crate::modules::analyzer::Analyzer;
use crate::modules::lib::write_report;
use crate::modules::socketlistener::SocketListener;

mod modules;

fn main() {

    let a=Analyzer::new("\\Device\\NPF_{DFADCF5E-E518-4EB5-A225-3126223CB9A2}", "report", 5);

}
