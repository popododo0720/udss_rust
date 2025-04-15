use clap::Parser;
use pcap::{Device, Capture, Activated, Offline, PacketHeader, Packet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use etherparse::{SlicedPacket, InternetSlice};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    interface: String,

    #[arg(short, long, default_value_t = 0)]
    count: i32,

    #[arg(short, long)]
    bind_interface: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    println!("{:#?}", args);
 
    let interface_name =  &args.interface;
    let bind_interface = &args.bind_interface;
    let filter_exp = "udp dst port 53 and less 1600";

    let mut pcap_handle = Capture::from_device(interface_name.as_str())?
    .buffer_size(268_435_456)
    .snaplen(2048)
    .promisc(true)
    .immediate_mode(true)
    .open()?;

    pcap_handle.filter(filter_exp, true)?;

    let mut packet_count = 0;

    while let Ok(packet) = pcap_handle.next_packet() {
        packet_count += 1;

        println!("--- Packet #{} ---", packet_count);
        println!("Timestamp: {}.{:06}", packet.header.ts.tv_sec, packet.header.ts.tv_usec);
        println!("Captured Length: {}", packet.header.caplen);
        println!("Original Length: {}", packet.header.len);

        // match SlicedPacket::from_ethernet(&packet.data) {
        //     Err(e) => {
        //         eprintln!("Packet parsing error: {:?}", e);
        //     }
        //     Ok(sliced_packet) => {
        //         if let Some(ip_info) = sliced_packet.ip {

        //         }
        //     }
        // }


        if args.count > 0 && packet_count >= args.count as u64 {
            break;
        }
    }

    println!("=== UDP Handler finished ===");
    Ok(())
}
