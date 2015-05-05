#ifndef __LINUX_SNIFFER_MAC_ADDRESS_H__
#define __LINUX_SNIFFER_MAC_ADDRESS_H__

#include <stdint.h>
#include <string>
#include <cstdio>

namespace LinuxSniffer {


class MacAddress
{
public:
	MacAddress() :
		b0(0),
		b1(0),
		b2(0),
		b3(0),
		b4(0),
		b5(0)
	{
	}

	explicit MacAddress(const uint8_t address[6]) :
		b0(address[0]),
		b1(address[1]),
		b2(address[2]),
		b3(address[3]),
		b4(address[4]),
		b5(address[5])
	{
	}

	std::string toString() const
	{
		char str[16];
		::sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x", b0, b1, b2, b3, b4, b5);
		return str;
	}

public:
	uint8_t b0;
	uint8_t b1;
	uint8_t b2;
	uint8_t b3;
	uint8_t b4;
	uint8_t b5;
}; // class MacAddress


} // namespace LinuxSniffer



#endif // __LINUX_SNIFFER_MAC_ADDRESS_H__
