# ESP8266 WarShipping
Low-cost WarShipping proof-of-concept with built-in geofencing & WiFi recon on the ESP8266.

## What is WarShipping?
WarShipping involves mailing a physical package that delivers an attack payload to a victim.  Typically these attacks will target large companies by addressing the package to a non-existent recipient, and having the package run a wireless payload while sitting inside a mail center, until it's shipped back to the return address.  

## WarShipping Proof-of-Concept

### Components
I wanted to show that a $5 payload could phish for user credentials and gather reconnaissance on a corporate network, so I used the following components: 
- ($2) [ESP8266 WiFi microcontroller]()
- ($2) [LiPo charging circuit]()
- ($6) [1800 mAh LiPo battery]()*  
<sub>*I ripped this out of a toy helicopter*</sub>


*insert image here*

The "D1 Mini" form factor makes these components stackable, but I soldered everything together to make it more stable for shipping.

*insert image here*

### Setup
Setup video + guide coming soon!

### Features
- Low-power mode
- Geofencing
- Basic WiFi reconnaissance
- Rogue AP for credential phishing
- Known network detection
- CSV logging

### To-Do
- CSV exports
- Deep sleep