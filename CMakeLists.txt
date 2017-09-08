cmake_minimum_required(VERSION 3.8)
project(sniffer)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES main.cpp Packet.cpp Packet.h PcapSession.cpp PcapSession.h)
add_executable(sniffer ${SOURCE_FILES})
target_link_libraries(sniffer pcap)