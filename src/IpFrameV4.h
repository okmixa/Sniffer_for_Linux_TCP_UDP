#ifndef __LINUX_SNIFFER_IP_FRAME_V4_H__
#define __LINUX_SNIFFER_IP_FRAME_V4_H__

#include <string>
#include "ProtocolFrame.h"

namespace LinuxSniffer {


class IpFrameV4 :
	public ProtocolFrame
{
public:
	IpFrameV4() :
		ProtocolFrame("Internet Protocol Version 4"),
		m_header_length(0),
		m_tos(0),
		m_package_size(0),
		m_id(0),
		m_flags(0),
		m_frag_offset(0),
		m_time_to_life(0),
		m_protocol(0),
		m_checksum(0)
	{
	}

	virtual ~IpFrameV4()
	{
	}

	virtual bool init(const uint8_t * buffer, size_t buffer_size);

	const std::string & getSourceAddress() const
	{
		return m_src_ip_addr;
	}

	const std::string & getDestinationAddress() const
	{
		return m_dest_ip_addr;
	}

	uint8_t getHeaderLength() const
	{
		return m_header_length;
	}

	uint8_t getTypeOfService() const
	{
		return m_tos;
	}

	uint16_t getPackageSize() const
	{
		return m_package_size;
	}

	uint16_t getId() const
	{
		return m_id;
	}

	uint8_t getFlags() const
	{
		return m_flags;
	}

	uint16_t getFragmintationOffset() const
	{
		return m_frag_offset;
	}

	uint8_t getTimeToLife() const
	{
		return m_time_to_life;
	}

	uint8_t getProtocolId() const
	{
		return m_protocol;
	}

	uint16_t getHeaderCheckSum() const
	{
		return m_checksum;
	}

public:
	static const uint8_t m_ipv4_version = 4;

private:
	void splitFragmentOffsetAndFlags();

private:
	std::string m_src_ip_addr;
	std::string m_dest_ip_addr;
	uint8_t m_header_length;
	uint8_t m_tos;
	uint16_t m_package_size;
	uint16_t m_id;
	uint8_t m_flags;
	uint16_t m_frag_offset;
	uint8_t m_time_to_life;
	uint8_t m_protocol;
	uint16_t m_checksum;
}; // class IpFrameV4


} // namespace LinuxSniffer



#endif // __LINUX_SNIFFER_IP_FRAME_V4_H__
