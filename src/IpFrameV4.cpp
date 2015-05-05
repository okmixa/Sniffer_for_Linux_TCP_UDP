#include <netinet/ip.h>
#include <arpa/inet.h>
#include "IpFrameV4.h"



using namespace LinuxSniffer;

bool IpFrameV4::init(const uint8_t * buffer, size_t buffer_size)
{
	if(buffer_size < sizeof(iphdr) || 0 == buffer)
		return false;
	const iphdr * ip_header = reinterpret_cast<const iphdr *>(buffer);
	if(m_ipv4_version != ip_header->version)
		return false;
	in_addr addr;
	addr.s_addr = ip_header->saddr;
	m_src_ip_addr = ::inet_ntoa(addr);
	addr.s_addr = ip_header->daddr;
	m_dest_ip_addr = ::inet_ntoa(addr);
	m_header_length = ip_header->ihl;
	m_tos = ip_header->tos;
	m_package_size = ip_header->tot_len;
	m_id = ip_header->id;
	m_frag_offset = ip_header->frag_off;
	m_time_to_life = ip_header->ttl;
	m_protocol = ip_header->protocol;
	m_checksum = ip_header->check;
	setDataOffset(m_header_length);
	splitFragmentOffsetAndFlags();
	return true;
}

void IpFrameV4::splitFragmentOffsetAndFlags()
{
	union
	{
		struct
		{
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint16_t flags : 3;
			uint16_t frag_offset : 13;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint16_t frag_offset : 13;
			uint16_t flags : 3;
#endif
		} spl;
		uint16_t num;
	} splitter;

	splitter.num = m_frag_offset;
	m_flags = splitter.spl.flags;
	m_frag_offset = splitter.spl.frag_offset;
}
