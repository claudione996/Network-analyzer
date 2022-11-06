#[derive(Debug)]
pub struct ParsedPacket {
    pub timestamp: usize,
    pub source_ip: String,
    pub destination_ip: String,
    pub port: String,
    pub protocol: String,
    pub weight: usize,
}

impl ParsedPacket {
    pub fn new(
        timestamp: usize,
        source_ip: String,
        destination_ip: String,
        port: String,
        protocol: String,
        weight: usize,
    ) -> Self {
        ParsedPacket {
            timestamp,
            source_ip,
            destination_ip,
            port,
            protocol,
            weight,
        }
    }
}