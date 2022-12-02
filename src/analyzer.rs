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
pub struct Analyzer{
    pub sl: SocketListener,
    pub report_writer: ReportWriter,
}

impl Analyzer{
    ///Creates the [SocketListener] and passes the aggregated data of its [Aggregator] to the [ReportWriter].
    /// # Arguments
    /// * `filename` - the name of the file on which the aggregated data will be printed
    /// * `timer` - u64 representing the period of time that must elapse (in the absence of pauses) before the ReportWriter is printed
    /// * `device` - The name of device to listen to
    /// # Examples
    /// Basic usage:
    /// ```rust
    /// use Network_analyzer::analyzer::Analyzer;
    /// let name_input = String::from("file.txt");
    /// let time:u64=5;
    /// let a=Analyzer::new("eth0", &name_input.as_str(), time);
    /// ```
    ///
    pub fn new(device:&str,filename:&str,timer:u64)->Self{
        let sl=SocketListener::new(device);
        let report_writer = ReportWriter::new(filename.to_string(), timer, sl.get_aggregated_data());
        Analyzer{sl,report_writer}
    }
    /// Pausing SocketListener and report writer
    pub fn pause(&self){
        println!("PAUSE: Pausing Network Analyzer");
        self.sl.pause();
        self.report_writer.pause();
    }
    /// Resuming SocketListener and report writer
    pub fn resume(&self){
        println!("RESUME: Resuming Network Analyzer");
        self.sl.resume();
        self.report_writer.resume();
    }
}
