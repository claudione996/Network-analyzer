#[derive(Debug)]
pub struct ParsedPacket {
    pub timestamp: String,
    pub source_ip: String,
    pub destination_ip: String,
    pub source_port: Option<usize>,
    pub destination_port: Option<usize>,
    pub protocol: String,
    pub size: usize,
}

impl ParsedPacket {
    pub fn new(
        timestamp: String,
        source_ip: String,
        destination_ip: String,
        source_port: Option<usize>,
        destination_port:Option<usize>,
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