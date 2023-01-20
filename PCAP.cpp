#include "PCAP.h"

struct Network {
    char* ssid;
    char* mac;
};

Network ssid_mac[64];

/* Create PCAP instance */
PCAP::PCAP() {
  for(int i = 0; i < 64; i++){
    ssid_mac[i].ssid = (char *)malloc(sizeof(char) * 33);
    ssid_mac[i].mac = (char *)malloc(sizeof(char) * 18);
  }
}

void PCAP::setup(const char *ssid, const char *mac){
  net_addr_asgn(ssid, mac);
}


void PCAP::net_addr_asgn(const char* ssid, const char *mac){
  int lsot = 0;
  while(strlen(ssid_mac[lsot].ssid) != 0){
    lsot++;
  }
  Serial.println("Adding physical Address:");
  Serial.println(ssid);
  Serial.println(mac);
  Serial.println(lsot);

  strlcpy(ssid_mac[lsot].ssid, ssid, 32);
  strlcpy(ssid_mac[lsot].mac, mac, 18);
}

char *PCAP::parseMac(uint8_t *mac){
  char* macStr = (char *)malloc(sizeof(char) * 17);
  memset(macStr, '\0', sizeof(char) * 17);

  sprintf(macStr, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

  return macStr;
}

char *PCAP::net_addr_r(uint8_t *mac){
  char *realMac = parseMac(mac);
  for(int i = 0; i < 64; i++){
    if(strncmp(realMac, ssid_mac[i].mac, 17) == 0){
      return ssid_mac[i].ssid;
    }
  }
  return realMac;
}


/* send file header to Serial */
void PCAP::startSerial(){
  serialwrite_32(magic_number);
  serialwrite_16(version_major);
  serialwrite_16(version_minor);
  serialwrite_32(thiszone);
  serialwrite_32(sigfigs);
  serialwrite_32(snaplen);
  serialwrite_32(network);
}

/* write packet to Serial */
void PCAP::newPacketSerial(uint32_t ts_sec, uint32_t ts_usec, uint32_t len, uint8_t* buf){
  uint32_t orig_len = len;
  uint32_t incl_len = len;
  
#if defined(ESP32)
  if(incl_len > snaplen) incl_len = snaplen; /* safty check that the packet isn't too big (I ran into problems with the ESP8266 here) */
#endif

  //begin actual code

  if(incl_len < 28) return;

  if((buf[12] == 0xc0) || (buf[12] == 0xa0)){
    Serial.println("-> DEAUTH DETECTED");
    return;
  }

  if((buf[12] == 0x80) || (buf[12] == 0x40) || (buf[12] == 0x50)) return;

  uint8_t* macOut = &buf[16];
  uint8_t* macIn = &buf[22];


  Serial.print(net_addr_r(macIn));
  Serial.print(" -> ");
  Serial.println(net_addr_r(macOut));

}
/* converts a 32 bit integer into 4 bytes */
void PCAP::escape32(uint32_t n, uint8_t* buf){
  buf[0] = n;
  buf[1] = n >>  8;
  buf[2] = n >> 16;
  buf[3] = n >> 24;
}

/* converts a 16 bit integer into 2 bytes */
void PCAP::escape16(uint16_t n, uint8_t* buf){
  buf[0] = n;
  buf[1] = n >>  8;
}

/* writes a 32 bit integer to Serial */
void PCAP::serialwrite_32(uint32_t n){
  uint8_t _buf[4];
  escape32(n, _buf);
  Serial.write(_buf, 4);
}

/* writes a 16 bit integer to Serial */
void PCAP::serialwrite_16(uint16_t n){
  uint8_t _buf[2];
  escape16(n, _buf);
  Serial.write(_buf, 2);
}


