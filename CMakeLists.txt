CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

SET(PROJECT sniffer)

PROJECT(${PROJECT})

SET(SRCDIR src)

INCLUDE_DIRECTORIES(${SRCDIR})

SET(HEADER_FILES
	${SRCDIR}/Sniffer.h
	${SRCDIR}/Analyzer.h
	${SRCDIR}/IpAnalyzer.h
	${SRCDIR}/MacAddress.h
	${SRCDIR}/ProtocolFrame.h
	${SRCDIR}/TransportProtocolFrame.h
	${SRCDIR}/EthernetFrameV2.h
	${SRCDIR}/IpFrameV4.h
	${SRCDIR}/TcpFrame.h
	${SRCDIR}/UdpFrame.h
)

SET(SOURCE_FILES
	${SRCDIR}/Sniffer.cpp
	${SRCDIR}/IpAnalyzer.cpp
	${SRCDIR}/EthernetFrameV2.cpp
	${SRCDIR}/IpFrameV4.cpp
	${SRCDIR}/TcpFrame.cpp
	${SRCDIR}/UdpFrame.cpp
	${SRCDIR}/Main.cpp
)

ADD_EXECUTABLE(${PROJECT} ${SOURCE_FILES} ${HEADER_FILES})
