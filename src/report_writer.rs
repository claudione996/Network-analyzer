use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::mem::needs_drop;
use std::os::raw::c_float;
use std::sync::{Arc, Condvar, Mutex};
use std::sync::mpsc::{channel, Sender};
use crate::parsed_packet::ParsedPacket;
use crate::report_entry::{Connection, ConnectionMetadata};

///enum to indicate the state to be assumed by the writing thread
#[derive(PartialEq,Debug)]
enum Command {
    PROCEED,
    PAUSE,
    EXIT
}

/// Struct for managing the writing of aggregated data to files
///
/// # Examples
/// Basic usage:
/// ```rust
/// use Network_analyzer::report_writer::ReportWriter;
/// use Network_analyzer::socket_listener::SocketListener;
///
/// let sl=SocketListener::new(device);
/// let name_input = String::from("file.txt");
/// let timer:u64=5;
/// let report_writer = ReportWriter::new(filename.to_string(), timer, sl.get_aggregated_data());
/// ```
///
/// Advanced usage: create multiple parsers listening to multiple devices
/// ```rust
///
/// ```
/// TODO: add Advanced usage
///
/// # Panics
/// TODO: add panic description
///
/// # Errors
/// TODO: add error description
///
/// # Remarks
/// TODO: add remarks
#[derive(Clone)]
pub struct ReportWriter{
    report_path: Arc<Mutex<String>>,
    rewrite_time: Arc<Mutex<u64>>,
    aggregated_data: Arc<Mutex<HashMap<Connection, ConnectionMetadata>>>,
    cmd: Arc<Mutex<Command>>,
    cv_cmd: Arc<Condvar>
}

impl ReportWriter {
    /// Creates a new Parser that receives pcap Packets through a channel and forwards ParsedPackets to the given Sender
    /// # Arguments
    /// * `report_path` -
    /// * `rewrite_time` -
    /// * `aggregated_data` -
    /// # Example
    /// Basic usage:
    /// ```rust
    /// use Network_analyzer::report_writer::ReportWriter;
    /// use Network_analyzer::socket_listener::SocketListener;
    ///
    /// let sl=SocketListener::new(device);
    /// let name_input = String::from("file.txt");
    /// let timer:u64=5;
    /// let report_writer = ReportWriter::new(filename.to_string(), timer, sl.get_aggregated_data());
    /// ```
    /// TODO: add Advanced usage
    ///
    /// # Panics
    /// TODO: add panic description
    ///
    /// # Errors
    /// TODO: add error description
    ///
    /// # Remarks
    /// TODO: add remarks
    pub fn new(report_path: String, rewrite_time: u64, aggregated_data: Arc<Mutex<HashMap<Connection, ConnectionMetadata>>>) -> Self {
        //generate all the Arcs
        let report_path = Arc::new(Mutex::new(report_path));
        let rwr_time = Arc::new(Mutex::new(rewrite_time));
        let cmd = Arc::new(Mutex::new(Command::PROCEED));
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
                        //release the lock on cmd
                        drop(cmd);
                        std::thread::sleep(std::time::Duration::from_secs(*rwr_time as u64));
                        //get the lock on cmd again and check if it is still "PROCEED"
                        let cmd = cmd_clone.lock().unwrap();
                        if *cmd == Command::PROCEED{
                            println!("ReportWriter thread awake, writing report");
                            let report_path = report_path_clone.lock().unwrap();
                            ReportWriter::write_report((*report_path).as_str(), aggregated_data_clone.clone());
                        }
                        else { println!("Report Writer received command: {:?} while sleeping so the report will not be written",*cmd); }
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

    pub fn resume(&self) {
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

    pub fn get_aggregated_data(&self) -> Arc<Mutex<HashMap<Connection, ConnectionMetadata>>> {
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

    //, aggregated_data: Arc<Mutex<HashMap<(String,usize),(String,usize,usize,usize)>>>
    fn write_report(filename:&str,aggregated_data: Arc<Mutex<HashMap<Connection, ConnectionMetadata>>>) {
        let aggregated_data = aggregated_data.lock().unwrap();

        let mut output = ReportWriter::create_dir_report(filename);
        writeln!(output, "|   Src IP address  |  Dst IP address   |  Src port |  Dst port |  Protocol |    Bytes      |  Initial timestamp    |   Final timestamp  |").expect("Error writing output file\n\r");
        writeln!(output, "| :---------------: | :---------------: | :-------: | :-------: | :-------: | :-----------: | :-------------------: | :----------------: |").expect("Error writing output file\n\r");

        for (conn, data) in aggregated_data.iter() {
            let port_src = match conn.source_port {
                Some(x) => x.to_string(),
                None => String::from("-"),
            };
            let port_dst = match conn.destination_port {
                Some(x) => x.to_string(),
                None => String::from("-"),
            };
            let bytes = data.size.to_string();
            //                  ip_src,     ip_dst,     port_src,   port_dst,  protocol,   bytes, first_timestamp,last_timestamp
            writeln!(output, "| {0:<15} \t| {1:<15} \t| {2:<5} \t | {3:<5} \t| {4:<7} \t| {5:<9} \t| {6:<15} \t| {7:<3}| ", conn.source_ip, conn.destination_ip, port_src, port_dst, conn.protocol, bytes, data.first_timestamp, data.last_timestamp).expect("Error writing output file\n\r");
        }
    }

    pub fn create_dir_report(filename:&str) -> BufWriter<File> {
        let res_dir=fs::create_dir("report");
        //TODO: handle error or success
        match res_dir {
            Ok(_) => {}
            Err(_) => {}
        }
        let mut path =String::from("report/");
        path.push_str(filename);
        path.push_str(".md");
        println!("{path}");
        let input=File::create(path.as_str()).expect("Error creating output file\n\r");
        let output = BufWriter::new(input);
        return output;

    }

}