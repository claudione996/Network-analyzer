use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::{BufWriter, ErrorKind, Write};
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
/// Advanced usage: Writing multiple report files (multiple ReportWriters one SocketListener)
/// ```rust
///use Network_analyzer::report_writer::ReportWriter;
/// use Network_analyzer::socket_listener::SocketListener;
///
/// let sl=SocketListener::new("eth0");
/// let filename_one = String::from("file1.txt");
/// let filename_two = String::from("file2.txt");
/// let timer_one:u64=5;
/// let timer_two:u64=7;
///
/// let report_writer_one = ReportWriter::new(filename_one, timer_one, sl.get_aggregated_data());
/// let report_writer_two = ReportWriter::new(filename_two, timer_two, sl.get_aggregated_data());
/// ```
///
///
/// # Panics
/// The associated thread will panic if the file or the report/folder cannot be opened/created
/// by the [ReportWriter::write_report] method or if the `aggregated_data` lock is poisoned
///
/// # Remarks
/// Is meant to be used in conjunction with one or multiple [SocketListener] or [Aggregator] instances,
/// unless custom implementation is needed, the [Analyzer] struct might be more suitable
#[derive(Clone)]
pub struct ReportWriter{
    report_path: Arc<Mutex<String>>,
    rewrite_time: Arc<Mutex<u64>>,
    aggregated_data: Arc<Mutex<HashMap<Connection, ConnectionMetadata>>>,
    cmd: Arc<Mutex<Command>>,
    cv_cmd: Arc<Condvar>
}

impl ReportWriter {
    /// Creates a new ReportWriter that prints on a file, a table with the aggregated data, after a time passed as parameter
    /// # Arguments
    /// * `report_path` - The name of the file on which the table with the aggregated data will be printed.
    /// * `rewrite_time` - The period of time that must elapse before writing to file
    /// * `aggregated_data` - Aggregated data that have as key [Connection] and as a value [ConnectionMetadata]
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
    ///
    ///
    /// # Panics
    /// Spawn a new thread that will panic if the file or the `report/` folder cannot be opened/created
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
            //println!("ReportWriter thread started");
            let mut loop1 = true;
            while loop1 {
                let mut cmd = cmd_clone.lock().unwrap();
                match *cmd {
                    Command::EXIT => {
                       // println!("ReportWriter thread exiting");
                        loop1 = false;
                    },
                    Command::PAUSE => {
                        //println!("ReportWriter thread paused");
                        cmd = cv_cmd_clone.wait_while(cmd, |cmd| *cmd == Command::PAUSE).unwrap();
                    },
                    Command::PROCEED => {
                        let rwr_time = rwr_time_clone.lock().unwrap();
                       // println!("ReportWriter thread proceeding, will wait for: {:?}", rwr_time);
                        //release the lock on cmd
                        drop(cmd);
                        std::thread::sleep(std::time::Duration::from_secs(*rwr_time as u64));
                        //get the lock on cmd again and check if it is still "PROCEED"
                        let cmd = cmd_clone.lock().unwrap();
                        if *cmd == Command::PROCEED{
                         //   println!("ReportWriter thread awake, writing report");
                            let report_path = report_path_clone.lock().unwrap();
                            ReportWriter::write_report((*report_path).as_str(), aggregated_data_clone.clone());
                        }
                        else { //println!("Report Writer received command: {:?} while sleeping so the report will not be written",*cmd);
                            }
                    }
                }
            }
        });
        ReportWriter { report_path, rewrite_time: rwr_time, aggregated_data, cmd, cv_cmd }
    }

    /// Stops the [ReportWriter], stopping the write timer after which, the print to file method is called
    pub fn pause(&self) {
        let mut cmd = self.cmd.lock().unwrap();
        *cmd = Command::PAUSE;
        self.cv_cmd.notify_one();
    }

    /// Reactivates the [ReportWriter], reactivating the write timer after which, the print to file method is called
    pub fn resume(&self) {
        let mut cmd = self.cmd.lock().unwrap();
        *cmd = Command::PROCEED;
        self.cv_cmd.notify_one();
    }

    /// Interrupts the loop of the [ReportWriter] thread, allowing the thread to end
    pub fn exit(&self) {
        let mut cmd = self.cmd.lock().unwrap();
        *cmd = Command::EXIT;
        self.cv_cmd.notify_one();
    }

    /// Modifies the value of the timer
    pub fn set_rewrite_time(&self, rewrite_time: u64) {
        let mut rwr_time = self.rewrite_time.lock().unwrap();
        *rwr_time = rewrite_time;
    }

    /// Return the value of the timer
    pub fn get_rewrite_time(&self) -> u64 {
        let rwr_time = self.rewrite_time.lock().unwrap();
        *rwr_time
    }

    /// Return aggregated data
    pub fn get_aggregated_data(&self) -> Arc<Mutex<HashMap<Connection, ConnectionMetadata>>> {
        Arc::clone(&self.aggregated_data)
    }

    ///Change the name of the file on which the aggregated data will be printed
    pub fn set_report_path(&self, new_report_path: String) {
        let mut report_path = self.report_path.lock().unwrap();
        *report_path = new_report_path;
    }

    ///Return the name of the file on which the aggregated data will be printed
    pub fn get_report_path(&self) -> String {
        let report_path = self.report_path.lock().unwrap();
        (*report_path).clone()
    }

    /// Prints on a markdown file a table representing the aggregated data
    /// # Arguments
    /// * `report_path` - The name of the file on which the table with the aggregated data will be printed.
    /// * `aggregated_data` - Aggregated data that have as key [Connection] and as a value [ConnectionMetadata]
    /// # Panics
    /// panics if the file or the `report/` folder cannot be created/opened
    /// also panics if the aggregated data lock is poisoned
    fn write_report(filename:&str,aggregated_data: Arc<Mutex<HashMap<Connection, ConnectionMetadata>>>) {
        let aggregated_data = aggregated_data.lock().unwrap();

        let mut output = ReportWriter::create_dir_report(filename);
        writeln!(output, "|   Src IP address  |  Dst IP address   |  Src port |  Dst port |  Protocol |    Bytes      |  Initial timestamp    |   Final timestamp  |").expect("Error writing output file\n\r");
        writeln!(output, "| :---------------: | :---------------: | :-------: | :-------: | :-------: | :-----------: | :-------------------: | :----------------: |").expect("Error writing output file\n\r");

        for (conn, data) in aggregated_data.iter() {
            writeln!(output,"{}{}",conn,data).expect("Error writing output file\n\r");
        }
    }

    /// Creates the directory `report/` if not present and the file `report/[filename].md`
    /// # Arguments
    /// * `filename` - The name of the file on which the table with the aggregated data will be printed.
    ///
    /// # Return
    /// The BufWriter pointing to the file `report/[filename].md`
    ///
    /// # Panics
    /// If the directory `report/` cannot be created because:
    /// - User lacks permissions to create directory at path.
    /// - Other errors returned by [std::fs::create_dir] **except for the `AlreadyExists` error**.
    ///
    /// or the file `report/[filename].md` cannot be created
    ///
    pub fn create_dir_report(filename:&str) -> BufWriter<File> {
        let res_dir=fs::create_dir("report");
        match res_dir {
            Ok(_) => {},
            Err(e) => {
                if e.kind() != ErrorKind::AlreadyExists {
                    panic!("Error creating report directory: {}", e);
                }
            }
        }
        let mut path =String::from("report/");
        path.push_str(filename);
        path.push_str(".md");
        //println!("{path}");
        let file=File::create(path.as_str()).expect("Error creating output file\n\r");
        let output = BufWriter::new(file);
        return output;

    }

}