#ifndef __LINUX_SNIFFER_UDP_FRAME_H__
#define __LINUX_SNIFFER_UDP_FRAME_H__

#include "TransportProtocolFrame.h"

namespace LinuxSniffer {


class UdpFrame :
	public TransportProtocolFrame
{
public:
	UdpFrame() :
		TransportProtocolFrame("User Datagram Protocol")
	{
	}

	virtual ~UdpFrame()
	{
	}

	virtual bool init(const uint8_t * buffer, size_t buffer_size);

	uint16_t getDatagramLength() const
	{
		return m_datagram_length;
	}

	uint16_t getCheckSum() const
	{
		return m_checksum;
	}

public:
	static const uint8_t m_protocol_id = 17;

private:
	uint16_t m_datagram_length;
	uint16_t m_checksum;
}; // class UdpFrame


} // namespace LinuxSniffer


#endif // __LINUX_SNIFFER_UDP_FRAME_H__
