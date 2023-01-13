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
    Serial.println("fs-dump");
    Serial.println("rem [file]");
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
}