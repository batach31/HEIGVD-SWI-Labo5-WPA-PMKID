#!/usr/bin/env python

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib

packets = rdpcap("PMKID_handshake.pcap")

ssid        = packets[145].info
APmac       = a2b_hex(packets[145].addr3.replace(':',''))
Clientmac   = a2b_hex(packets[145].addr1.replace(':',''))
pmkid       = "TODO find pmkid"

passPhrase = "admin123"

pmk = pbkdf2(hashlib.sha1, str.encode(passPhrase), ssid, 4096, 32)

computed_pmkid = hmacsha1 = hmac.new(pmk,str.encode("PMK Name")+APmac+Clientmac,hashlib.sha1)[:6]

print("real pmkid : ", pmkid)
print("computed pmkid : ", computed_pmkid)