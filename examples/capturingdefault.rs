use Network_analyzer::init_default;

fn main() {
    let mut cap = init_default();
    while let Ok(packet) = cap.next_packet() {
        println!("received packet! {:?}", packet);
    }
}