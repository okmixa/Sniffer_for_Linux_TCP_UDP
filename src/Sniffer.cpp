#include <errno.h>
#include <netpacket/packet.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/sockios.h>
#include "Sniffer.h"


using namespace LinuxSniffer;


Sniffer::Sniffer(const std::string & device_name, bool sniff_all)
	throw(SnifferError) :
	m_device(device_name),
	m_sniff_all(sniff_all),
	m_is_promiscuouse_mode_set(false),
	m_is_stopping(false),
	mp_frame_buffer(0)
{
	makeSocket();
	mp_frame_buffer = new unsigned char[m_frame_buffer_size];
}

Sniffer::~Sniffer()
{
	deinit();
}

void Sniffer::deinit()
{
	::close(m_socket);
	unsetPromiscuousMode();
	delete [] mp_frame_buffer;
}

bool Sniffer::addAnalyzer(Analyzer * analyzer)
{
	return m_analyzers.insert(analyzer).second;
}

bool Sniffer::removeAnalyzer(Analyzer * analyzer)
{
	return m_analyzers.erase(analyzer) > 0;
}

void Sniffer::makeSocket()
	throw(SnifferError)
{
	m_socket = ::socket(AF_PACKET, SOCK_RAW, ::htons(ETH_P_ALL));
	if(-1 == m_socket)
		throw SnifferError(::strerror(errno));
	try
	{
		bindSocketToDevice();
		if(m_sniff_all)
			setPromiscuousMode();
	}
	catch(...)
	{
		deinit();
		throw;
	}
}

void Sniffer::bindSocketToDevice()
	throw(SnifferError)
{
	const size_t device_name_len = m_device.length() + 1;
	char * device = new char[device_name_len];
	::strcpy(device, m_device.c_str());
	device[m_device.length()] = '\0';
	int setopt_result = ::setsockopt(m_socket, SOL_SOCKET,
		SO_BINDTODEVICE, device, device_name_len);
	delete [] device;
	if(-1 == setopt_result)
		throw SnifferError(::strerror(errno));
}

void Sniffer::setPromiscuousMode() throw(SnifferError)
{
	ifreq iface;
	::strcpy(iface.ifr_name, m_device.c_str());
	if(::ioctl(m_socket, SIOCGIFFLAGS, &iface) < 0)
		throw SnifferError(::strerror(errno));
	iface.ifr_flags |= IFF_PROMISC;
	if(::ioctl(m_socket, SIOCSIFFLAGS, &iface) < 0)
		throw SnifferError(::strerror(errno));
	m_is_promiscuouse_mode_set = true;
}

void Sniffer::unsetPromiscuousMode()
{
	if(!m_is_promiscuouse_mode_set)
		return;
	ifreq iface;
	::strcpy(iface.ifr_name, m_device.c_str());
	if(::ioctl(m_socket, SIOCGIFFLAGS, &iface) >= 0)
	{
		iface.ifr_flags &= ~IFF_PROMISC;
		if(::ioctl(m_socket, SIOCSIFFLAGS, &iface) >= 0)
			m_is_promiscuouse_mode_set = false;
	}
}

void Sniffer::start() throw(SnifferError)
{
	while(!m_is_stopping)
	{
		ssize_t length = ::recvfrom(m_socket, mp_frame_buffer,
			m_frame_buffer_size, 0, 0, 0);
		if(-1 == length)
			throw SnifferError(::strerror(errno));
		runAnalyzers(mp_frame_buffer, length);
	}
}

void Sniffer::runAnalyzers(const unsigned char * frame, size_t frame_size)
{
	for(std::set<Analyzer *>::iterator it = m_analyzers.begin();
		m_analyzers.end() != it; ++it)
	{
		Analyzer * analyzer = *it;
		if(0 != analyzer)
			analyzer->analyze(frame, frame_size);
	}
}

void Sniffer::stop()
{
	m_is_stopping = true;
}
