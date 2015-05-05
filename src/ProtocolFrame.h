#ifndef __LINUX_SNIFFER_PROTOCOL_FRAME_H__
#define __LINUX_SNIFFER_PROTOCOL_FRAME_H__

#include <string>
#include <sys/types.h>
#include <stdint.h>

namespace LinuxSniffer {


class ProtocolFrame
{
public:
	ProtocolFrame(const std::string & protocol_name) :
		m_protocol_name(protocol_name),
		m_data_offset(0)
	{
	}

	virtual ~ProtocolFrame()
	{
	}

	const std::string & getName() const
	{
		return m_protocol_name;
	}

	virtual bool init(const uint8_t * buffer, size_t buffer_size) = 0;

	size_t getDataOffset() const
	{
		return m_data_offset;
	}

protected:
	void setDataOffset(size_t offset)
	{
		m_data_offset = offset;
	}

private:
	const std::string m_protocol_name;
	size_t m_data_offset;
}; // class ProtocolFrame


} // namespace LinuxSniffer


#endif // __LINUX_SNIFFER_PROTOCOL_FRAME_H__
