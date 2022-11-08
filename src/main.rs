use crate::modules::socketlistener::SocketListener;

mod modules;

fn main() {
    let device = "en0";
    let sock=SocketListener::new(device);
    std::thread::sleep(std::time::Duration::from_secs(5));
    println!("pause");
    sock.pause();
    println!("resume");
    std::thread::sleep(std::time::Duration::from_secs(5));
    println!("pause");
    sock.pause();
}
