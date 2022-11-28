use core::fmt;
use std::fmt::Formatter;

/// This struct represents a directional connection between two hosts.
/// It is used as a key in the aggregated data map.
/// It represents source and destination hosts through their IP addresses and ports and specifies the type of connection through the `protocol` attribute.
/// The source IP address and the source port are Option to allow representation of ICMP communications that are not associated to ports.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Connection {
    pub source_ip: String,
    pub destination_ip: String,
    pub source_port: Option<usize>,
    pub destination_port: Option<usize>,
    pub protocol: String,
}

impl Connection {
    /// Creates a new Connection struct.
    /// # Arguments
    /// * `source_ip` - The source IP address.
    /// * `destination_ip` - The destination IP address.
    /// * `source_port` - The source port.
    /// * `destination_port` - The destination port.
    /// * `protocol` - The protocol.
    /// # Returns
    /// A new Connection struct.
    pub fn new(
        source_ip: String,
        destination_ip: String,
        source_port: Option<usize>,
        destination_port: Option<usize>,
        protocol: String,
    ) -> Self {
        Connection {
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            protocol,
        }
    }
}

/// Display implementation for the Connection struct.
/// It is used to print the Connection struct as a markdown table entry.
impl fmt::Display for Connection {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let port_src = match self.source_port {
            Some(x) => x.to_string(),
            None => String::from("-"),
        };
        let port_dst = match self.destination_port {
            Some(x) => x.to_string(),
            None => String::from("-"),
        };
        write!(f,"| {0:<15} \t| {1:<15} \t| {2:<5} \t | {3:<5} \t| {4:<7} \t|", self.source_ip, self.destination_ip, port_src, port_dst, self.protocol)
    }
}

/// This struct represents aggregated data collected about a connection.
/// It is used as a value in the aggregated data map.
/// It contains the number of bytes exchanged between the two hosts and the timestamp of the first and last packet exchanged.
#[derive(Debug)]
pub struct ConnectionMetadata {
pub size: usize,
pub first_timestamp: String,
pub last_timestamp: String,
}

impl ConnectionMetadata {
    /// Creates a new ConnectionMetadata struct.
    /// # Arguments
    /// * `size` - The number of bytes exchanged.
    /// * `first_timestamp` - The timestamp of the first packet exchanged.
    /// * `last_timestamp` - The timestamp of the last packet exchanged.
    /// # Returns
    /// A new ConnectionMetadata struct.
    pub fn new(size: usize, first_timestamp: String, last_timestamp: String) -> Self {
        ConnectionMetadata {
            size,
            first_timestamp,
            last_timestamp,
        }
    }
}

impl fmt::Display for ConnectionMetadata {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f," {0:<9} \t| {1:<15} \t| {2:<3}|",self.size,self.first_timestamp,self.last_timestamp)
    }
}

