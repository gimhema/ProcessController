use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::{Packet};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use std::env;

fn main() {
    // 네트워크 인터페이스 선택
    let interface_name = env::args().nth(1).expect("Usage: cargo run <interface>");
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter()
        .find(|iface| iface.name == interface_name)
        .expect("Error: Interface not found");

    // 패킷 캡처 채널 생성
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Error creating datalink channel: {}", e),
    };

    // 패킷 수신 루프
    loop {
        match rx.next() {
            Ok(packet) => {
                // Ethernet 패킷을 IPv4로 파싱
                if let Some(ethernet_packet) = pnet::packet::ethernet::EthernetPacket::new(packet) {
                    if let Some(ip_packet) = Ipv4Packet::new(ethernet_packet.payload()) {
                        // TCP 패킷 확인
                        if ip_packet.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                            if let Some(tcp_packet) = TcpPacket::new(ip_packet.payload()) {
                                println!(
                                    "Captured a TCP packet: {}:{} -> {}:{}",
                                    ip_packet.get_source(),
                                    tcp_packet.get_source(),
                                    ip_packet.get_destination(),
                                    tcp_packet.get_destination()
                                );

                                // 페이로드(데이터) 출력
                                if let Some(payload) = tcp_packet.payload().get(0..) {
                                    println!("Payload: {:?}", payload);
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("An error occurred while reading: {}", e);
            }
        }
    }
}
