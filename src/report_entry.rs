use core::fmt;
use std::fmt::Formatter;

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Connection {
    pub source_ip: String,
    pub destination_ip: String,
    pub source_port: Option<usize>,
    pub destination_port: Option<usize>,
    pub protocol: String,
}

impl Connection {
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


#[derive(Debug)]
pub struct ConnectionMetadata {
pub size: usize,
pub first_timestamp: String,
pub last_timestamp: String,
}

impl ConnectionMetadata {
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

