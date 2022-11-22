use std::net::IpAddr;

use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::NetworkInterface;

fn handle_transport_protocol(source: IpAddr, destination: IpAddr, protocol: IpNextHeaderProtocol, packet: &[u8]) {
    match protocol {
        IpNextHeaderProtocols::Tcp => {
            let tcp = TcpPacket::new(packet);
            if let Some(tcp) = tcp {
                println!(
                    "PACKET [source]: {} [destination]: {} [source]: {} [destination]: {} length: {}",
                    source, destination, tcp.get_source(), tcp.get_destination(), packet.len()
                );
            } else {
                println!("Uncorrect TCP packet")
            }
        }
        _ => println!("Unsupported protocol")
    }
}

fn handle_ipv4_packet(packet: &EthernetPacket) {
    let header = Ipv4Packet::new(packet.payload());
    if let Some(header) = header {
        handle_transport_protocol(
            IpAddr::V4(header.get_source()),
            IpAddr::V4(header.get_destination()),
            header.get_next_level_protocol(),
            packet.payload(),
        )
    } else {
        println!("Uncorrect packet: {:?}", packet.payload())
    }
}

fn handle_ethernet_frame(interface: &NetworkInterface, ethernet: &EthernetPacket) {
    let interface_name = interface.name.as_str();
    println!("Interface: {}", interface_name);
    
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => handle_ipv4_packet(ethernet),
        _ => print!(
            "Unknown packet: {}",
            ethernet.packet().len(), 
        ),
    }
}

fn main() {
    let interface_name: String = String::from("eth0");
    let interface_names_match = |iface: &NetworkInterface| iface.name == interface_name;
    let interfaces = pnet::datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap_or_else(|| panic!("no interface"));

    let (_, mut rx) = match pnet::datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("No ethernet"),
        Err(e) => panic!("Protocol panic: {}", e),
    };

    loop {
        match rx.next() {
            Ok(packet) => {
                handle_ethernet_frame(&interface, &EthernetPacket::new(packet).unwrap())
            }
            Err(e) => panic!("no packet {}", e),
        }
    }
}
