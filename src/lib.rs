pub mod network_analyzer{

    use std::io;
    use pcap::{Active, Capture, Device};
    use crate::network_analyzer::network_analyzer_components::looper::Looper;
    pub mod network_analyzer_components;

    pub fn select_default() -> Capture<Active> {

        let main_device = Device::lookup().unwrap().unwrap();
        let mut cap = Capture::from_device(main_device).unwrap()
            .promisc(true)
            .snaplen(5000)
            .open().unwrap();

        return cap;
    }

    pub fn select_device() -> Capture<Active> {

        let mut i=0;
        // list all of the devices pcap tells us are available
        let dev_list= Device::list().expect("device lookup failed");
        for device in &dev_list {
            i+=1;
            println!("{})  {:?}",i, device.desc.as_ref().unwrap());
        }

        let mut input_line = String::new();
        io::stdin()
            .read_line(&mut input_line)
            .expect("Failed to read line");
        let mut number: usize = input_line.trim().parse().expect("Input not an integer");
        number-=1;

        let device = dev_list[number].clone();

        println!("Selected {:?}",device.desc.as_ref().unwrap());

        let mut cap = Capture::from_device(device).unwrap()
            .promisc(true)
            .snaplen(5000)
            .open().unwrap();

        return cap;
    }

    pub fn print_packets(mut cap:Capture<Active>){
        while let Ok(packet) = cap.next_packet() {
            println!("received packet! {:?}", packet);
        }
    }

    /// only the print function is executed in the background, the capture is still blocking
    pub fn print_packets_background(mut cap:Capture<Active>){
        let mut looper = Looper::new(|p| println!("received packet! {}",p),|| println!("CLEANUP() CALLED"));
        while let Ok(packet) = cap.next_packet() {
            let p_str = format!("{:?}",packet);
            looper.send(p_str);
        }
    }
}



