use crate::modules::socketlistener::SocketListener;

pub struct Analizer{
}

impl Analizer{
    pub fn new(device:&str,filename:&str,timer:u64)->Self{
        let sl=SocketListener::new(device,filename);
        std::thread::sleep(std::time::Duration::from_secs(timer));
        sl.stop();
        Analizer{}
    }
}