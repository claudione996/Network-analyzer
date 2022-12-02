use std::thread::sleep;
use std::time;
use network_analyzer::select_device;
use network_analyzer::socket_listener::SocketListener;

fn main() {

    //select the device from all the network devices of the pc
    println!("Select the device to sniff:");
    let device_name = select_device();

    //A socketListener instantiates and manages for you one parser and one aggregator
    //so that you can just specify the device you want to collect aggregated data from
    let sl : SocketListener = SocketListener::new(&device_name);

    //i get the reference to the aggregated data in the same way i do with the aggregator
    let agg_data = sl.get_aggregated_data();

    //i will wait for some data to be produced
    let time  = time::Duration::from_secs(5);
    sleep(time);

    //i print the aggregated data
    {
        println!("First print:");
        let agg_data = agg_data.lock().unwrap();
        for (conn,data) in agg_data.iter() {
            println!("{}{}",conn,data);
        }
    }

    //i can also decide to pause the sniffing process
    sl.pause();
    //so that the threads of parser and aggregato are still available but doing nothing while
    sleep(time);
    //i can resume it
    sl.resume();

    {
        println!("Second print:");
        let agg_data = agg_data.lock().unwrap();
        for (conn,data) in agg_data.iter() {
            println!("{}{}",conn,data);
        }
    }


}