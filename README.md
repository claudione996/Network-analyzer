# Network analyzer library

Network-analyzer is a **Rust language** crate that allows the interception of incoming and outgoing traffic
through the network interfaces of a computer and aggregate it by network address/port

In particular, each network address/port will correspond to the protocols that were transported, the cumulative number of bytes transmitted, the timestamp of the first and last
occurrence of the exchange

## Installation

<details>

  <summary>Windows dependencies&emsp;<img alt="" src="https://user-images.githubusercontent.com/12531596/203198673-59a69a92-124f-4a9f-abb0-60712c1a08d8.png" width="35px"/></summary>

In order to correctly run Network-analyzer on Windows systems you need to:

- Install [Npcap](https://npcap.com/#download).

- Download the [Npcap SDK](https://npcap.com/#download).

- Add the SDK's ```/Lib``` or ```/Lib/x64``` folder to your ```LIB``` environment variable.

</details>

<details>

  <summary>Linux dependencies&emsp;<img alt="" src="https://user-images.githubusercontent.com/12531596/203199234-94ef76ce-f4fc-4694-948f-645dede73999.png" width="35px"/></summary>

In order to correctly run Network-analyzer on Linux systems, install the libraries and header files for the libpcap library:
- On Debian based Linux:
```sh
sudo apt-get install libpcap-dev
```
- On Fedora Linux:
```sh
sudo apt-get install libpcap-devel
```
Note that if you are not running as root, you need to set capabilities to inspect a network adapter:

```sh
sudo setcap cap_net_raw,cap_net_admin=eip <your/Network-analyzer/executable/path>
```

</details>


<details>

  <summary>MacOS dependencies&emsp;<img alt="" src="https://user-images.githubusercontent.com/12531596/203199712-198d9a9d-e9c5-478d-8501-5fc6bdeed061.png" width="35px"/></summary>

MacOS natively has all the dependencies you need to build and run Network-analyzer

</details>

## Usage

### Analyzer Example

A simple example of the potential of Network-analyzer is given by the Struct Analyzer

```rust
fn main() {
    let name_input = String::from("file.txt");
    let time: u64 = 5;
    let a = Analyzer::new("eth0", &name_input.as_str(), time);
}
```
We pass three parameters to the Analyzer:
- The device on which we listen for packet traffic
- The name of the file on which we will print the analysis result
- The time interval in seconds after which the analysis result will be printed out
  
the call to new prints aggregated data by network address/port in the specified file (if it does not exist it is created) after the specified time

### Other Components

The Analyzer uses other Struct offered by Crate to function

<details>

  <summary>Parser</summary>

The Parser is a Struct used to listen to pcap packets in transit from a device and transform them into ParsedPackets, i.e. packets that have fields useful for analysis, such as:
- entry IP address
- outgoing IP address
- input port
- outgoing port
- protocol

</details>
<details>

  <summary>Aggregator</summary>

The Aggregator is a Struct that takes the packets sent by its channel's Sender, and aggregates them into a Struct (HashMap): which has the network address/port as key
</details>
<details>

  <summary>SocketListener</summary>

Socket listener is a Struct that was created for the purpose of allowing the user not to deal with the implementation of the parser and aggregator.
In fact, this Struct creates and links an aggregator and a parser and thus allows aggregated data to be obtained
</details>

<details>

  <summary>ReportWriter</summary>

Socket listener is a Struct that is responsible for taking aggregated data (e.g. from Aggregator) and printing them to files
</details>


### Examples of Advanced Uses
As explained earlier, the various Struct are used to run the Analyzer, which involves the use of a SocketListener (and thus a Parser and Aggregator) and a ReportWriter.
But these Struct can be used freely by the user to realise different situations

- Parallel reading from multiple devices (multiple Parsers one Aggregator)

```rust
fn main() {
    // I am creating a channel where the parser will send the parsed packets
    let (tx, rx) = channel();
    // I create a new parser listening to device "eth0" and sending
    // the parsed packets to the channel i just created
    let parser1 = Parser::new("eth0", tx.clone());
    let parser2 = Parser::new("eth1", tx.clone());
    // Now I can use rx to receive the parsed packets from all the parsers
    while let Ok(parsed_packet) = rx.recv() {
       println!("Received packet: {:?}", parsed_packet);
    }
}
```

- Parallel reading from multiple devices and writing multiple report files ( multiple Analyzers )
```rust
fn main() {
    let timer:u64=5;
    let filename_one = String::from("file1.txt");
    let filename_two = String::from("file2.txt");
    let a_one=Analyzer::new("eth0", &filename_one.as_str(), timer);
    let a_two=Analyzer::new("eth1", &filename_two.as_str(), timer);
}
```

- Writing multiple report files ( multiple ReportWriters one SocketListener )
```rust
fn main() {
    let sl=SocketListener::new("eth0");
    let filename_one = String::from("file1.txt");
    let filename_two = String::from("file2.txt");
    let timer_one:u64=5;
    let timer_two:u64=7;
    
    let report_writer_one = ReportWriter::new(filename_one, timer_one, sl.get_aggregated_data());
    let report_writer_two = ReportWriter::new(filename_two, timer_two, sl.get_aggregated_data());
}
```
