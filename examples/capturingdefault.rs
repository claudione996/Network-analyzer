use Network_analyzer::*;

fn main() {
   /* let mut cap = init_default();
    while let Ok(packet) = cap.next_packet() {
        println!("received packet! {:?}", packet);
    }*/

    let mut cap = select_debug();
    //print_packets(cap);
    send_to_aggregator(cap);
}
