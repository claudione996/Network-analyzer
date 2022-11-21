use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use crate::aggregator::Aggregator;
use crate::parser::Parser;
use crate::report_entry::{Connection, ConnectionMetadata};

/// Struct that creates and associates a [Parser], starting from device, with an [Aggregator]
///
/// # Examples
/// Basic usage:
/// ```rust
/// use std::{thread, time};
/// use Network_analyzer::socket_listener::SocketListener;
/// // I am creating a SocketListener passing it the name of the device that will be used by the parser
/// let sl=SocketListener::new("eth0");
/// // I am waiting five seconds to populate the aggregator
/// let five_sec = time::Duration::from_secs(5);
/// thread::sleep(five_sec);
/// // I am retrieving data from the aggregator
/// let data=sl.get_aggregated_data();
///
/// ```
pub struct SocketListener{
    parser: Parser,
    aggregator:Aggregator,
    device:String,
}

impl SocketListener {
    /// Creates a SocketListener by creating and connecting an Aggregator and a Parser
    /// # Arguments
    /// * `device_str` - The name of device to listen to
    /// # Example
    /// Basic usage:
    /// ```rust
    ///use std::{thread, time};
    /// use Network_analyzer::socket_listener::SocketListener;
    /// // I am creating a SocketListener passing it the name of the device that will be used by the parser
    /// let sl=SocketListener::new("eth0");
    /// ```
    pub fn new(device_str:&str) -> Self {
        let aggregator=Aggregator::new();
        let aggregator_tx=aggregator.get_sender();
        let parser=Parser::new(device_str, aggregator_tx.clone());

        let device=String::from(device_str);
        SocketListener{parser,aggregator,device}
    }

    /// Pauses the parser of SocketListener from receiving packets if it is not already paused
    pub fn pause(&self){
    self.parser.stop_iter_cap();
    }

    /// Resumes the parser of SocketListener from receiving packets if it was paused, otherwise does nothing
    pub fn resume(&self){
    self.parser.resume_iter_cap();
    }

    /// Interrupts the loop of the parser thread, allowing the thread to end
    pub fn exit(&self){
        self.parser.exit_iter_cap();
    }

    /// Returns aggregated data from the Aggregator of SocketListener
    pub fn get_aggregated_data(&self)-> Arc<Mutex<HashMap<Connection,ConnectionMetadata>>>{
        self.aggregator.get_aggregated_data()
    }

}
