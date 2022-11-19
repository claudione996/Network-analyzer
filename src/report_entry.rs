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