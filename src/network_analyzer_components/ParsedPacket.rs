#[derive(Debug)]
pub struct ParsedPacket {
    pub timestamp: String,
    pub source_ip: String,
    pub destination_ip: String,
    pub port: String,
    pub protocol: String,
    pub size: usize,
}

impl ParsedPacket {
    pub fn new(
        timestamp: String,
        source_ip: String,
        destination_ip: String,
        port: String,
        protocol: String,
        size: usize,
    ) -> Self {
        ParsedPacket {
            timestamp,
            source_ip,
            destination_ip,
            port,
            protocol,
            size,
        }
    }
}