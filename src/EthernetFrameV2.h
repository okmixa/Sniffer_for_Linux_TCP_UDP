#ifndef __LINUX_SNIFFER_ETHERNET_FRAME_V2_H__
#define __LINUX_SNIFFER_ETHERNET_FRAME_V2_H__

#include <cstring>
#include "ProtocolFrame.h"
#include "MacAddress.h"

namespace LinuxSniffer {

class EthernetFrameV2 :
	public ProtocolFrame
{
public:
	EthernetFrameV2() :
		ProtocolFrame("Ethernet Version 2")
	{
	}

	virtual ~EthernetFrameV2()
	{
	}

	virtual bool init(const uint8_t * buffer, size_t buffer_size);

	const MacAddress & getSourceMacAddress() const
	{
		return m_src_mac_addr;
	}

	const MacAddress & getDestinationMacAddress() const
	{
		return m_dest_mac_addr;
	}

	static const uint8_t (& getEthernetType())[2]
	{
		static bool is_init = false;
		static uint8_t type[2];
		if(!is_init)
		{
			 ::memcpy(type, "\x08\x00", 2);
			 is_init = true;
		}
		return type;
	}

private:
	MacAddress m_src_mac_addr;
	MacAddress m_dest_mac_addr;
}; // class EthernetFrameV2

} // namespace LinuxSniffer


#endif // __LINUX_SNIFFER_ETHERNET_FRAME_V2_H__
