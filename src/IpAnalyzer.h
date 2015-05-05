#ifndef __LINUX_SNIFFER_IP_ANALYZER_H__
#define __LINUX_SNIFFER_IP_ANALYZER_H__

#include <utility>
#include "Analyzer.h"


namespace LinuxSniffer {

class TransportProtocolFrame;

class IpAnalyzer :
	public Analyzer
{
public:
	virtual ~IpAnalyzer() { }
	virtual void analyze(const uint8_t * frame, size_t frame_size);

private:
	size_t tryEthV2Analyze(const uint8_t * frame, size_t frame_size);
	std::pair<size_t, uint8_t> tryIpV4Analyze(const uint8_t * frame,
		size_t frame_size);
	size_t tryTcpAnalyze(const uint8_t * frame, size_t frame_size);
	size_t tryUdpAnalyze(const uint8_t * frame, size_t frame_size);
	void printTransportProtocolFrame(const TransportProtocolFrame & frame) const;
}; // class IpAnalyzer


} // namespace LinuxSniffer


#endif // __LINUX_SNIFFER_IP_ANALYZER_H__
