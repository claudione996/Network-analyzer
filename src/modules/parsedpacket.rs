#[derive(Debug)]
pub struct ParsedPacket {
    pub timestamp: usize,
    pub source_ip: String,
    pub destination_ip: String,
    pub source_port: usize,
    pub destination_port: usize,
    pub protocol: String,
    pub size: usize,
}

impl ParsedPacket {
    pub fn new(
        timestamp: usize,
        source_ip: String,
        destination_ip: String,
        source_port: usize,
        destination_port:usize,
        protocol: String,
        size: usize,
    ) -> Self {
        ParsedPacket {
            timestamp,
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            protocol,
            size,
        }
    }
}