use pcap::{Active, Capture, Device};

pub fn init_default() -> Capture<Active> {

    let main_device = Device::lookup().unwrap().unwrap();
    let mut cap = Capture::from_device(main_device).unwrap()
        .promisc(true)
        .snaplen(5000)
        .open().unwrap();

    return cap;
}
