
    use std::sync::mpsc::{channel,Sender};

    #[derive(Clone)]
    pub struct Looper<Message: Send+'static>{
        tx: Sender<Message>
    }

    impl <Message: Send+'static> Looper<Message>{
        pub fn new(
            process: impl Fn(Message) + Send + 'static,
            cleanup: impl Fn() + Send + 'static
        ) -> Self {
            let(tx,rx) = channel::<Message>();

            std::thread::spawn( move || {
                let mut loop1 = true;
                while loop1 {
                    let msg = rx.recv();
                    match msg {
                        Ok(m) => process(m),
                        Err(e) => {
                            println!("Error: {}", e);
                            loop1 = false;
                        }
                    }
                }
                cleanup();
            });
            Looper { tx }
        }

        pub fn send(&self, msg: Message){
            self.tx.send(msg).unwrap();
        }
    }



//fn main() {
//    println!("Hello, world!");
//    //declare a list of strings
//    let list = vec!["one".to_string(),"two".to_string(),"three".to_string()];
//    let l1 : Looper<String> = Looper::new(|m| println!("processing: {}",m),|| println!("CLEANUP() CALLED"));
//    //send the list to the looper
//    for i in list {
//        l1.send(i);
//    }
//    l1.send("ultimo".to_string());
//}
