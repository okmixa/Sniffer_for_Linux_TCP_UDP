#include <iostream>
#include <signal.h>
#include "Sniffer.h"
#include "IpAnalyzer.h"

using namespace LinuxSniffer;

namespace LinuxSniffer {

class Application
{
public:
	Application(const std::string & device, bool sniff_all);
	~Application();
	void start();
	void stop();

private:
	IpAnalyzer * mp_analyzer;
	Sniffer * mp_sniffer;
} * application; // class Application

Application::Application(const std::string & device, bool sniff_all) :
	mp_analyzer(new IpAnalyzer()),
	mp_sniffer(new Sniffer(device, sniff_all))
{
	mp_sniffer->addAnalyzer(mp_analyzer);
}

Application::~Application()
{
	stop();
	delete mp_sniffer;
	delete mp_analyzer;
}

void Application::start()
{
	mp_sniffer->start();
}

void Application::stop()
{
	mp_sniffer->stop();
}

void quit(int signum)
{
	application->stop();
	delete application;
	application = 0;
}

} // namespace LinuxSniffer

int main(int argc, char ** argv)
{
	if(argc < 2)
	{
		std::cerr << "Too few arguments\n";
		return 1;
	}

	application = 0;
	std::string device(argv[1]);
	bool sniff_all = argc > 2 && argv[2][0] == 'a';
	::signal(SIGINT, quit);

	try
	{
		application = new Application(device, sniff_all);
		application->start();
	}
	catch(const SnifferError & error)
	{
		std::cerr << "Sniffer error: " << error.what() << std::endl;
	}
	catch(const std::exception & error)
	{
		std::cerr << "Standard error: " << error.what() << std::endl;
	}
	catch(...)
	{
		std::cerr << "Unknown error\n";
	}
	delete application;
	application = 0;
	return 0;
}
