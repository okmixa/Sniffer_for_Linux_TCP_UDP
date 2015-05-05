#ifndef __LINUX_SNIFFER_TRANSPORT_PROTOCOL_FRAME_H__
#define __LINUX_SNIFFER_TRANSPORT_PROTOCOL_FRAME_H__

#include "ProtocolFrame.h"


namespace LinuxSniffer {


class TransportProtocolFrame :
	public ProtocolFrame
{
public:
	TransportProtocolFrame(const std::string & protocol_name) :
		ProtocolFrame(protocol_name),
		m_src_port(0),
		m_dest_port(0)
	{
	}

	virtual ~TransportProtocolFrame()
	{
	}

	uint16_t getSourcePort() const
	{
		return m_src_port;
	}

	uint16_t getDestinationPort() const
	{
		return m_dest_port;
	}

protected:
	void setSourcePort(uint16_t port)
	{
		m_src_port = port;
	}

	void setDestinationPort(uint16_t port)
	{
		m_dest_port = port;
	}

private:
	uint16_t m_src_port;
	uint16_t m_dest_port;
}; // class TransportProtocolFrame


} // namespace LinuxSniffer


#endif // __LINUX_SNIFFER_TRANSPORT_PROTOCOL_FRAME_H__
