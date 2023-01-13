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

char hostname[128];

const uint8_t channels[] = {1, 6, 11};
const bool wpa2 = false; 
const bool appendSpaces = true;

// run-time variables
char emptySSID[32];
uint8_t channelIndex = 0;
uint8_t macAddr[6];
uint8_t wifi_channel = 1;
uint32_t currentTime = 0;
uint32_t packetSize = 0;
uint32_t packetCounter = 0;
uint32_t attackTime = 0;
uint32_t packetRateTime = 0;

char *ssids[64] PROGMEM;

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

// Random MAC generator
void randomMac() {
  for (int i = 0; i < 6; i++){
     macAddr[i] = random(256);
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
	Serial.begin(9600);
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

  // for random generator
  randomSeed(os_random());

  // set packetSize
  packetSize = sizeof(beaconPacket);
  if (wpa2) {
    beaconPacket[34] = 0x31;
  } else {
    beaconPacket[34] = 0x21;
    packetSize -= 26;
  }

  // generate random mac address
  randomMac();

  // start serial
  Serial.begin(115200);
  Serial.println();

  // get time
  currentTime = millis();

  // start WiFi
  WiFi.mode(WIFI_OFF);
  wifi_set_opmode(STATION_MODE);

  // Set to default WiFi channel
  wifi_set_channel(channels[0]);
}

bool spamming_beacons = false;

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
    Serial.println("fs-dump");
    Serial.println("rem [file]");
    Serial.println("spam-beacons [file]");
    Serial.println("stop-beacons");
    Serial.println("esptap-help");
    Serial.println("esptap [arguments]");
  }else if(strcmp(args[0], "esptap-help") == 0){
    Serial.println("ESPTAP help:");
    Serial.println("esptap connected");
    Serial.println("esptap returns [base64-encoded-payload]");
    Serial.println("esptap load [file]");
    Serial.println("esptap mode [crash-clients/steal-passwords/sniff-device-info]");
    Serial.println("esptap logging [all/http-only/dns-only/none]");
    Serial.println("esptap captive-portal [yes/no]");
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
    unsigned int str_l = encode_base64((unsigned char *) total_buf_in, strlen(total_buf_in), (unsigned char *) encoded);
    Serial.print(encoded);
  }else if(strcmp(args[0], "set-content") == 0){
    char *file = (char *)malloc(sizeof(char) * strlen(args[1]) + 2);
    strcpy(file, "/");
    strcat(file, args[1]);
    char content[4096];

    decode_base64((unsigned char *)args[2], (unsigned char *) content);
    
    File confwr = SPIFFS.open(file, "w+");
    confwr.print(content);
    confwr.close();

    Serial.print("Wrote ");
    Serial.print(strlen(content) * 8);
    Serial.print(" bytes to ");
    Serial.println(file);
  }else if(strcmp(args[0], "decode") == 0){

  }else if(strcmp(args[0], "fs-dump") == 0){
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
  }if(strcmp(args[0], "spam-beacons")){
    char *file = (char *)malloc(sizeof(char) * strlen(args[1]) + 2);
    strcpy(file, "/");
    strcat(file, args[1]);
    File ssid_handle = SPIFFS.open(file, "r");
    int i = 0;
  
    while(ssid_handle.available()){
      if(i > 75) break;
      const char *jb = ssid_handle.readStringUntil('\n').c_str();
      char *this_ssid = malloc(sizeof(char) * strlen(jb) + 1);
      strcpy(this_ssid, jb);
      strcat(this_ssid, "\n");
      ssids[i] = (char *) malloc((32  + 1 )* sizeof(char));
      strcpy(ssids[i], this_ssid);
      i++;
    }
    Serial.print("Read ");
    Serial.print(i);
    Serial.println(" SSIDS to memory");


    spamming_beacons = true;
  }if(strcmp(args[0], "stop-beacons")){
    spamming_beacons = false;
  }else{ 
    Serial.println("No such command found! type help to get a list of commands");
  }
}

void loop() {
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
  if(spamming_beacons){
    currentTime = millis();

    if (currentTime - attackTime > 100) {
      attackTime = currentTime;

      // temp variables
      int i = 0;
      int j = 0;
      int ssidNum = 1;
      char tmp;
      int ssidsLen = 64;//STATIC DEFINE PLEASE CHANGE LATER
      bool sent = false;

      // Go to next channel
      nextChannel();

      while (i < ssidsLen) {


        char *ssid = ssids[i];

        while(strlen(ssid) != 32){
          if(strlen(ssid) > 32){
            return;
          }
          strcat(ssid, ".");
        }

        macAddr[5] = ssidNum;
        ssidNum++;

        // write MAC address into beacon frame
        memcpy(&beaconPacket[10], macAddr, 6);
        memcpy(&beaconPacket[16], macAddr, 6);

        // reset SSID
        memcpy(&beaconPacket[38], emptySSID, 32);

        // write new SSID into beacon frame
        memcpy_P(&beaconPacket[38], &ssids[i], 32);

        // set channel for beacon frame
        beaconPacket[82] = wifi_channel;

        for (int k = 0; k < 3; k++) {
          packetCounter += wifi_send_pkt_freedom(beaconPacket, packetSize, 0) == 0;
          delay(1);
        }

        i += j;
      }
    }

    // show packet-rate each second
    if (currentTime - packetRateTime > 1000) {
      packetRateTime = currentTime;
      Serial.print("BEACON SPAMMING!12e1 Packets/s: ");
      Serial.println(packetCounter);
      packetCounter = 0;
    }
  }
}