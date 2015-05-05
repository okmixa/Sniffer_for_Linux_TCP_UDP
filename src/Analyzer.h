#ifndef __LINUX_SNIFFER_ANALYZER_H__
#define __LINUX_SNIFFER_ANALYZER_H__

#include <sys/types.h>
#include <stdint.h>

namespace LinuxSniffer {


class Analyzer
{
public:
	virtual ~Analyzer() { }
	virtual void analyze(const uint8_t * frame, size_t frame_size) = 0;
}; // class Analyzer


} // namespace LinuxSniffer


#endif // __LINUX_SNIFFER_ANALYZER_H__
