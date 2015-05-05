#include <netinet/udp.h>
#include "UdpFrame.h"

using namespace LinuxSniffer;


bool UdpFrame::init(const uint8_t * buffer, size_t buffer_size)
{
	if(buffer_size < sizeof(udphdr))
		return false;
	const udphdr * udp_header = reinterpret_cast<const udphdr *>(buffer);
	setSourcePort(udp_header->source);
	setDestinationPort(udp_header->dest);
	setDataOffset(sizeof(udphdr));
	m_datagram_length = udp_header->len;
	m_checksum = udp_header->check;
	return true;
}
