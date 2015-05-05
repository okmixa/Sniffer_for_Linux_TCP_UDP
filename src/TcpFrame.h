#ifndef __LINUX_SNIFFER_TCP_FRAME_H__
#define __LINUX_SNIFFER_TCP_FRAME_H__

#include "TransportProtocolFrame.h"

namespace LinuxSniffer {


class TcpFrame :
	public TransportProtocolFrame
{
public:
	TcpFrame() :
		TransportProtocolFrame("Transmission Control Protocol"),
		m_sequence_number(0),
		m_ascknowledgment_number(0),
		m_flag_fin(false),
		m_flag_syn(false),
		m_flag_rst(false),
		m_flag_psh(false),
		m_flag_ack(false),
		m_flag_urg(false),
		m_window_size(0),
		m_checksum(0),
		m_urgent_ptr(0)
	{
	}

	virtual ~TcpFrame()
	{
	}

	virtual bool init(const uint8_t * buffer, size_t buffer_size);

	uint32_t getSequenceNumber() const
	{
		return m_sequence_number;
	}

	uint32_t getAscknowledgmentNumber() const
	{
		return m_ascknowledgment_number;
	}

	bool isFinFlagSet() const
	{
		return m_flag_fin;
	}

	bool isSynFlagSet() const
	{
		return m_flag_syn;
	}

	bool isRstFlagSet() const
	{
		return m_flag_rst;
	}

	bool isPshFlagSet() const
	{
		return m_flag_psh;
	}

	bool isAckFlagSet() const
	{
		return m_flag_ack;
	}

	bool isUrgFlagSet() const
	{
		return m_flag_urg;
	}

	uint16_t getWindowSize() const
	{
		return m_window_size;
	}

	uint16_t getCheckSum() const
	{
		return m_checksum;
	}

	uint16_t getUrgentPtr() const
	{
		return m_urgent_ptr;
	}

public:
	static const uint8_t m_protocol_id = 6;

private:
	uint32_t m_sequence_number;
	uint32_t m_ascknowledgment_number;
	bool m_flag_fin;
	bool m_flag_syn;
	bool m_flag_rst;
	bool m_flag_psh;
	bool m_flag_ack;
	bool m_flag_urg;
	uint16_t m_window_size;
	uint16_t m_checksum;
	uint16_t m_urgent_ptr;
}; // class TcpFrame


} // namespace LinuxSniffer


#endif // __LINUX_SNIFFER_TCP_FRAME_H__
