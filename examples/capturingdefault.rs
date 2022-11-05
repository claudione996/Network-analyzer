use Network_analyzer::{select_default, print_packets, select_device};

fn main() {
   /* let mut cap = init_default();
    while let Ok(packet) = cap.next_packet() {
        println!("received packet! {:?}", packet);
    }*/

    let mut cap = select_device();
    print_packets(cap);
}