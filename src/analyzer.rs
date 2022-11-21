use std::io;
use crate::report_writer::ReportWriter;
use crate::socket_listener::SocketListener;

/// Struct that associates a [SocketListener] with a [ReportWriter].
///
/// # Examples
/// Basic usage:
/// ```rust
/// use Network_analyzer::analyzer::Analyzer;
/// let name_input = String::from("file.txt");
/// let time=5;
/// let a=Analyzer::new("eth0", &name_input.as_str(), time);
/// ```
///
///
/// # Panics
/// TODO: add panic description
///
/// # Errors
/// TODO: add error description
///
/// # Remarks
/// TODO: add remarks description
pub struct Analyzer{
    pub sl: SocketListener,
    pub report_writer: ReportWriter,
}

impl Analyzer{
    ///Creates the [SocketListener] and passes the aggregated data of its [Aggregator] to the [ReportWriter].
    ///
    /// # Examples
    /// Basic usage:
    /// ```rust
    /// use Network_analyzer::analyzer::Analyzer;
    /// let name_input = String::from("file.txt");
    /// let time=5;
    /// let a=Analyzer::new("eth0", &name_input.as_str(), time);
    /// ```
    ///
    /// # Panics
    /// TODO: add panic description
    ///
    /// # Errors
    /// TODO: add error description
    ///
    /// # Remarks
    /// TODO: add remarks description
    pub fn new(device:&str,filename:&str,timer:u64)->Self{
        let sl=SocketListener::new(device);
        let report_writer = ReportWriter::new(filename.to_string(), timer, sl.get_aggregated_data());
        Analyzer{sl,report_writer}
    }
    /// Pausing SocketListener and report writer
    pub fn pause(&self){
        println!("choice 1: pausing SocketListener and report writer");
        self.sl.pause();
        self.report_writer.pause();
    }
    /// Resuming SocketListener and report writer
    pub fn resume(&self){
        println!("choice 2: resuming SocketListener and report writer");
        self.sl.resume();
        self.report_writer.resume();
    }

    /// Interrupts the threads created with [SocketListener] and [ReportWriter]
    pub fn exit(&self){
        self.sl.exit();
        self.report_writer.exit();
    }
}