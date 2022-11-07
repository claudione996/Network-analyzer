use Network_analyzer::*;
use Network_analyzer::network_analyzer_components::socketlistener::SocketListener;

fn main() {
    let device = "\\Device\\NPF_{DFADCF5E-E518-4EB5-A225-3126223CB9A2}";
    let sock=SocketListener::new(device);
    std::thread::sleep(std::time::Duration::from_secs(5));
    println!("pause");
    sock.pause();
    println!("resume");
    std::thread::sleep(std::time::Duration::from_secs(5));
    println!("pause");
    sock.pause();
}
