use aya::{include_bytes_aligned, Ebpf};
use aya::programs::{Xdp, XdpFlags};
use aya::maps::AsyncPerfEventArray;
use aya::util::online_cpus;
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, warn, error};
use std::net::Ipv4Addr;
use tokio::{ signal, time::Duration };
use anyhow::Context as _;
use bytes::BytesMut;

// RUST_LOG=info cargo run
// RUST_LOG=info cargo run --features vlan_enabled

// filter.c 에서 packet_info
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct PacketInfo {
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    vlan_tci: u16,
    vlan_proto: u16,
    ip_id: u16,
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    dns_tr_id: u16,
    // dns_query: [u8; 50],
}

// 바이트슬라이스 packetinfo 로 변환위한 unsafe trait
unsafe impl aya::Pod for PacketInfo {}

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "enp11s0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    env_logger::init();

    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "eBPF/filter.o"
    ))?;

    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let program: &mut Xdp = bpf.program_mut("xdp_filter").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .expect("failed to attach XDP program");
    info!("XDP program attached to interface {}", opt.iface);

    // map 과 bpf 객체 라이프타임 분리 - take_map 으로 소유권가져옴옴
    let perf_map = bpf.take_map("perf_output")
        .context("Failed to take ownership of perf_output map. Check map name in C code.")?; // 에러 컨텍스트 추가

    let mut perf_array = AsyncPerfEventArray::try_from(perf_map)?;

    // 온라인상태 CPU 코어어
    let cpu_ids = online_cpus().map_err(|(msg, io_err)| {
        anyhow::Error::new(io_err)
            .context(msg.to_string())
            .context("Failed to get online CPUs")
    })?;
    info!("Listening on {} CPUs", cpu_ids.len());

    // 모든 CPU 코어에 perf buffer
    for cpu_id in cpu_ids {
        // perf array 는 static 라이프타임 - buf도 static
        let mut buf = perf_array.open(cpu_id, None)?;

        // buf가 static - async move 
        tokio::spawn(async move {
            let mut buffers = (0..10) 
                .map(|_| BytesMut::with_capacity(std::mem::size_of::<PacketInfo>() + 10)) 
                .collect::<Vec<_>>();

            info!("[CPU {}] Waiting for events...", cpu_id);

            loop {
                let events = match buf.read_events(&mut buffers).await {
                    Ok(events) => events,
                    Err(e) => {
                        error!("[CPU {}] Error reading events: {}", cpu_id, e);
                        continue;
                    }
                };

                if events.lost > 0 {
                    warn!("[CPU {}] Lost {} events", cpu_id, events.lost);
                }

                for i in 0..events.read {
                    let buf_slice = &buffers[i];
                
                    if buf_slice.len() >= std::mem::size_of::<PacketInfo>() {
                        let packet_info: &PacketInfo = unsafe { &*(buf_slice.as_ptr() as *const PacketInfo) };
                        
                        let src_mac = format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                            packet_info.src_mac[0], packet_info.src_mac[1], packet_info.src_mac[2], 
                            packet_info.src_mac[3], packet_info.src_mac[4], packet_info.src_mac[5]);
                
                        let dst_mac = format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                            packet_info.dst_mac[0], packet_info.dst_mac[1], packet_info.dst_mac[2], 
                            packet_info.dst_mac[3], packet_info.dst_mac[4], packet_info.dst_mac[5]);
                
                        let vlan_tci = packet_info.vlan_tci;
                        let vlan_proto = packet_info.vlan_proto;
                        let vlan_id = vlan_tci & 0x0FFF;

                        let ip_id = packet_info.ip_id;

                        let src_ip_addr = Ipv4Addr::from(u32::from_be(packet_info.src_ip));
                        let dst_ip_addr = Ipv4Addr::from(u32::from_be(packet_info.dst_ip));
                
                        let src_port = u16::from_be(packet_info.src_port);
                        let dst_port = u16::from_be(packet_info.dst_port);

                        let dns_tr_id = u16::from_be(packet_info.dns_tr_id);

                        info!("mac: [{}] -> [{}] vlan_tci: {} vlan_proto: {} \nip_id: {}, ip: {} -> {} \nsrc_port: {}, dst_port: {} \n dns_tr_id: {}", 
                            src_mac, dst_mac, vlan_id, vlan_proto, 
                            ip_id, src_ip_addr, dst_ip_addr, 
                            src_port, dst_port
                            , dns_tr_id);
                    }
                }
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;

    info!("Shutting down ...");
    tokio::time::sleep(Duration::from_secs(1)).await;

   Ok(()) 
}