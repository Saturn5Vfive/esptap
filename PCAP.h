/*
  ===========================================
       Copyright (c) 2017 Stefan Kremser
              github.com/spacehuhn
  ===========================================
*/

#ifndef PCAP_h
#define PCAP_h

#include <Arduino.h>
#include "SPI.h"

class PCAP
{
  public:
    PCAP();
	
    void startSerial();
	
    void flushFile();
    void closeFile();
    void setup(const char *ssid, const char *mac);

    void newPacketSerial(uint32_t ts_sec, uint32_t ts_usec, uint32_t len, uint8_t* buf);
	String filename = "capture.cap";
	
    uint32_t magic_number = 0xa1b2c3d4;
    uint16_t version_major = 2;
    uint16_t version_minor = 4;
    uint32_t thiszone = 0;
    uint32_t sigfigs = 0;
    uint32_t snaplen = 2500;
    uint32_t network = 105;

  private:

    void escape32(uint32_t n, uint8_t* buf);
    void escape16(uint16_t n, uint8_t* buf);
    char* net_addr_r(uint8_t *mac);
    char* parseMac(uint8_t *mac);
    void net_addr_asgn(const char *ssid, const char *mac);
	
    void serialwrite_16(uint16_t n);
    void serialwrite_32(uint32_t n);
};

#endif

