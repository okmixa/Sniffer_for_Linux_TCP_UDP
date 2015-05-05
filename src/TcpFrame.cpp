#include <netinet/tcp.h>
#include "TcpFrame.h"

using namespace LinuxSniffer;


bool TcpFrame::init(const uint8_t * buffer, size_t buffer_size)
{
	if(buffer_size < sizeof(tcphdr))
		return false;
	const tcphdr * tcp_header = reinterpret_cast<const tcphdr *>(buffer);
	setSourcePort(tcp_header->source);
	setDestinationPort(tcp_header->dest);
	setDataOffset(tcp_header->doff);
	m_sequence_number = tcp_header->seq;
	m_ascknowledgment_number = tcp_header->ack_seq;
	m_flag_fin = tcp_header->fin != 0;
	m_flag_syn = tcp_header->syn != 0;
	m_flag_rst = tcp_header->rst != 0;
	m_flag_psh = tcp_header->psh != 0;
	m_flag_ack = tcp_header->ack != 0;
	m_flag_urg = tcp_header->urg != 0;
	m_window_size = tcp_header->window;
	m_checksum = tcp_header->check;
	m_urgent_ptr = tcp_header->urg_ptr;
	return true;
}
