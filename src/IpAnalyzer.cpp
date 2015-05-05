#include <iostream>
#include "IpAnalyzer.h"
#include "EthernetFrameV2.h"
#include "IpFrameV4.h"
#include "TcpFrame.h"
#include "UdpFrame.h"

using namespace LinuxSniffer;

void IpAnalyzer::analyze(const uint8_t * frame, size_t frame_size)
{
	const size_t ip_offset = tryEthV2Analyze(frame, frame_size);
	if(0 == ip_offset)
		return;

	const uint8_t * ip_frame = &frame[ip_offset];
	const size_t ip_frame_size = frame_size - ip_offset;
	std::pair<size_t, uint8_t> ip_analyze_result =
		tryIpV4Analyze(ip_frame, ip_frame_size);
	if(0 == ip_analyze_result.first)
		return;


	const uint8_t * transport_frame = ip_frame + ip_analyze_result.first;
	const size_t transport_frame_size = ip_frame_size - ip_analyze_result.first;
	size_t application_protocol_data_offset;
	switch(ip_analyze_result.second)
	{
	case TcpFrame::m_protocol_id:
		application_protocol_data_offset = tryTcpAnalyze(
			transport_frame, transport_frame_size);
		break;
	case UdpFrame::m_protocol_id:
		application_protocol_data_offset = tryUdpAnalyze(
			transport_frame, transport_frame_size);
		break;
	default:
		std::cout << "======= Unsupported transport protocol ======\n";
	}

	std::cout << std::endl;
}

size_t IpAnalyzer::tryEthV2Analyze(const uint8_t * frame, size_t frame_size)
{
	EthernetFrameV2 eth_frame;
	if(!eth_frame.init(frame, frame_size))
		return 0;

	std::cout << "====== " << eth_frame.getName() << " ======\n" <<
		"Source MAC Address: " << eth_frame.getSourceMacAddress().toString() <<
		std::endl << "Destination MAC Address: " <<
		eth_frame.getDestinationMacAddress().toString() << std::endl;

	return eth_frame.getDataOffset();
}

std::pair<size_t, uint8_t> IpAnalyzer::tryIpV4Analyze(const uint8_t * frame,
	size_t frame_size)
{
	IpFrameV4 ip_frame;
	if(!ip_frame.init(frame, frame_size))
		return std::make_pair(0, 0);

	std::cout << "====== " << ip_frame.getName() << " ======\n" <<
		"Source IP Address: " << ip_frame.getSourceAddress() << std::endl <<
		"Destination IP Address: " << ip_frame.getDestinationAddress() <<
		std::endl <<
		"Header Length: " << std::dec <<
		static_cast<uint32_t>(ip_frame.getHeaderLength()) << std::endl <<
		"Type Of Service: " <<
		static_cast<uint32_t>(ip_frame.getTypeOfService())<< std::endl <<
		"Package Size: "<< ip_frame.getPackageSize() << std::endl <<
		"Identification: " << ip_frame.getId() << std::endl <<
		"Flags: " << static_cast<uint32_t>(ip_frame.getFlags())<< std::endl <<
		"Fragmentation Offset: " <<	ip_frame.getFragmintationOffset() <<
		 std::endl <<
		"Time To Live: " <<	static_cast<uint32_t>(ip_frame.getTimeToLife()) <<
		 std::endl <<
		"Transport Protocol ID: " <<
		static_cast<uint32_t>(ip_frame.getProtocolId()) << std::endl <<
		"CRC-16 Header CheckSum:" << std::hex << ip_frame.getHeaderCheckSum() <<
		 std::endl;
	return std::make_pair(ip_frame.getDataOffset(), ip_frame.getProtocolId());
}

size_t IpAnalyzer::tryTcpAnalyze(const uint8_t * frame, size_t frame_size)
{
	TcpFrame tcp_frame;
	if(!tcp_frame.init(frame, frame_size))
		return 0;

	printTransportProtocolFrame(tcp_frame);

	std::cout << std::dec <<
	"Sequence Number: " << tcp_frame.getSequenceNumber() << std::endl <<
	"Ascknowledgment Number: " << tcp_frame.getAscknowledgmentNumber() <<
	std::endl <<
	"Window Size: " << tcp_frame.getWindowSize() << std::endl <<
	"Urgent Pointer: " << tcp_frame.getUrgentPtr() << std::endl <<
	"Flags:\n" <<
	"    FIN: " << std::boolalpha << tcp_frame.isFinFlagSet() << std::endl <<
	"    SYN: " << tcp_frame.isSynFlagSet() << std::endl <<
	"    RST: " << tcp_frame.isRstFlagSet() << std::endl <<
	"    PSH: " << tcp_frame.isPshFlagSet() << std::endl <<
	"    ACK: " << tcp_frame.isAckFlagSet() << std::endl <<
	"    URG: " << tcp_frame.isUrgFlagSet() << std::endl <<
	"CheckSum: " << std::hex << tcp_frame.getCheckSum() << std::endl;

	return tcp_frame.getDataOffset();
}

size_t IpAnalyzer::tryUdpAnalyze(const uint8_t * frame, size_t frame_size)
{
	UdpFrame udp_frame;
	if(!udp_frame.init(frame, frame_size))
		return 0;

	printTransportProtocolFrame(udp_frame);
	std::cout << std::dec <<
		"Datagram Length: " << std::dec << udp_frame.getDatagramLength() <<
		 std::endl <<
		 "Datagram CheckSum: " << std::hex << udp_frame.getCheckSum() <<
		 std::endl;
	return udp_frame.getDataOffset();
}

void IpAnalyzer::printTransportProtocolFrame(
	const TransportProtocolFrame & frame) const
{
	std::cout << "====== " << frame.getName() << " ======\n" <<
		std::dec << "Source Port: " << frame.getSourcePort() << std::endl <<
		"Destination Port: " << frame.getDestinationPort() <<
		std::endl;
}
