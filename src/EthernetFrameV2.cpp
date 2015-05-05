#include <cstring>
#include <netinet/ether.h>
#include "EthernetFrameV2.h"

using namespace LinuxSniffer;


bool EthernetFrameV2::init(const uint8_t * buffer, size_t buffer_size)
{
	if(buffer_size < sizeof(ether_header))
		return false;
	const ether_header * hdr = reinterpret_cast<const ether_header *>(buffer);
	if(::memcmp(&hdr->ether_type, getEthernetType(), sizeof(getEthernetType())))
		return false;
	setDataOffset(sizeof(ether_header));
	m_src_mac_addr = MacAddress(hdr->ether_shost);
	m_dest_mac_addr = MacAddress(hdr->ether_shost);
	return true;
}
