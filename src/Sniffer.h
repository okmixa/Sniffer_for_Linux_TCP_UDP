#ifndef __LINUX_SNIFFER_SHIFFER_H__
#define __LINUX_SNIFFER_SHIFFER_H__


#include <set>
#include <string.h>
#include <stdexcept>
#include "Analyzer.h"


namespace LinuxSniffer {

class SnifferError :
	public std::runtime_error
{
public:
	SnifferError(const std::string & message) throw() :
		std::runtime_error(message)
	{
	}

	virtual ~SnifferError() throw()
	{
	}
}; // class SnifferError


class Sniffer
{
public:
	explicit Sniffer(const std::string & device_name, bool sniff_all = false)
		throw(SnifferError);
	virtual ~Sniffer();
	bool addAnalyzer(Analyzer * analyzer);
	bool removeAnalyzer(Analyzer * analyzer);
	void start() throw(SnifferError);
	void stop();

private:
	void deinit();
	void makeSocket() throw(SnifferError);
	void bindSocketToDevice() throw(SnifferError);
	void setPromiscuousMode() throw(SnifferError);
	void unsetPromiscuousMode();
	void runAnalyzers(const unsigned char * frame, size_t frame_size);

private:
	Sniffer(const Sniffer &);
	Sniffer & operator = (const Sniffer &);

private:
	const std::string m_device;
	const bool m_sniff_all;
	std::set<Analyzer *> m_analyzers;
	int m_socket;
	bool m_is_promiscuouse_mode_set;
	bool m_is_stopping;
	unsigned char * mp_frame_buffer;
	static const size_t m_frame_buffer_size = 65536;
}; // class Sniffer


} // namespace LinuxSniffer


#endif // __LINUX_SNIFFER_SHIFFER_H__
