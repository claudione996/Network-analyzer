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

Mac OS natively has all the dependencies you need to build and run Network-analyzer

</details>

## Usage

### Analyser Example

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
  
the call to new prints aggregated data by network/port address in the specified file (if it does not exist it is created) after the specified time

### Altri componenti

### Spiegazione dei componenti (Parser, Socketlistener, Aggregator, Reportwriter)

**Parser:** [Spiegazione parser] [Codice esempio]
**Aggregator:** [Spiegazione aggregator] [codice esempio]

**Socketlistener:** [Spiegazione socketlistener] [codice esempio]

**Reportwriter:** [Spiegazione reportwriter] [codice esempio]



### Esempi di utilizzo avanzati

- [Esempio di lettura parallela da più device ( più parser un aggregator )]
- [Esempio di scrittura di più file di report ( più reportwriter un aggregator )]
- [Esempio di lettura parallela da più device e scrittura di più file di report ( più analyzer )]
