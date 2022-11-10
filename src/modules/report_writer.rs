use std::collections::HashMap;
use std::mem::needs_drop;
use std::os::raw::c_float;
use std::sync::{Arc, Condvar, Mutex};
use std::sync::mpsc::{channel, Sender};
use crate::modules::lib::write_report;
use crate::modules::parsedpacket::ParsedPacket;

#[derive(PartialEq)]
enum Command {
    PROCEED,
    PAUSE,
    EXIT
}

#[derive(Clone)]
pub struct ReportWriter{
    report_path: Arc<Mutex<String>>,
    rewrite_time: Arc<Mutex<u64>>,
    aggregated_data: Arc<Mutex<HashMap<(String,usize),(String,usize,usize,usize)>>>,
    cmd: Arc<Mutex<Command>>,
    cv_cmd: Arc<Condvar>
}

impl ReportWriter {
    pub fn new(report_path: String, rewrite_time: u64, aggregated_data: Arc<Mutex<HashMap<(String, usize),(String, usize, usize, usize)>>>) -> Self {
        //generate all the Arcs
        let report_path = Arc::new(Mutex::new(report_path));
        let rwr_time = Arc::new(Mutex::new(rewrite_time));
        let cmd = Arc::new(Mutex::new(Command::PAUSE));
        let cv_cmd = Arc::new(Condvar::new());

        //clone the Arcs for the thread
        let report_path_clone = report_path.clone();
        let cmd_clone =cmd.clone();
        let cv_cmd_clone = cv_cmd.clone();
        let rwr_time_clone = rwr_time.clone();
        let aggregated_data_clone = aggregated_data.clone();

        std::thread::spawn( move || {
            println!("ReportWriter thread started");
            let mut loop1 = true;
            while loop1 {
                let mut cmd = cmd_clone.lock().unwrap();
                match *cmd {
                    Command::EXIT => {
                        println!("ReportWriter thread exiting");
                        loop1 = false;
                    },
                    Command::PAUSE => {
                        println!("ReportWriter thread paused");
                        cmd = cv_cmd_clone.wait_while(cmd, |cmd| *cmd == Command::PAUSE).unwrap();
                    },
                    Command::PROCEED => {
                        let rwr_time = rwr_time_clone.lock().unwrap();
                        println!("ReportWriter thread proceeding, will wait for: {:?}", rwr_time);
                        drop(cmd);
                        //release the lock on cmd
                        std::thread::sleep(std::time::Duration::from_secs(*rwr_time as u64));
                        //get the lock on cmd again and check if it is still proceed
                        let cmd = cmd_clone.lock().unwrap();
                        if *cmd == Command::PROCEED{
                            println!("ReportWriter thread awoken, writing report");
                            let report_path = report_path_clone.lock().unwrap();
                            write_report((*report_path).as_str(), aggregated_data_clone.clone());
                        }
                    }
                }
            }
        });
        ReportWriter { report_path, rewrite_time: rwr_time, aggregated_data, cmd, cv_cmd }
    }

    pub fn pause(&self) {
        let mut cmd = self.cmd.lock().unwrap();
        *cmd = Command::PAUSE;
        self.cv_cmd.notify_one();
    }

    pub fn proceed(&self) {
        let mut cmd = self.cmd.lock().unwrap();
        *cmd = Command::PROCEED;
        self.cv_cmd.notify_one();
    }

    pub fn exit(&self) {
        let mut cmd = self.cmd.lock().unwrap();
        *cmd = Command::EXIT;
        self.cv_cmd.notify_one();
    }

    pub fn set_rewrite_time(&self, rewrite_time: u64) {
        let mut rwr_time = self.rewrite_time.lock().unwrap();
        *rwr_time = rewrite_time;
    }

    pub fn get_rewrite_time(&self) -> u64 {
        let rwr_time = self.rewrite_time.lock().unwrap();
        *rwr_time
    }

    pub fn get_aggregated_data(&self) -> Arc<Mutex<HashMap<(String, usize),(String, usize, usize, usize)>>> {
        Arc::clone(&self.aggregated_data)
    }

    pub fn set_report_path(&self, new_report_path: String) {
        let mut report_path = self.report_path.lock().unwrap();
        *report_path = new_report_path;
    }

    pub fn get_report_path(&self) -> String {
        let report_path = self.report_path.lock().unwrap();
        (*report_path).clone()
    }

}