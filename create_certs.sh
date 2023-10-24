#!/bin/sh

# This shell script will generate the certificates needed to run the demo

#
# Any of the four following commands will generate a valid root.pem and root.crt 
#

#openssl genrsa -aes128 -out root.pem 4096
#openssl req -new -x509 -sha256 -key root.pem -out root.crt -days 3650  -subj "/C=ES/ST=Galicia/L=Vigo/O=ACME/OU=ACME Head Office/CN=127.0.0.1"

#openssl genrsa -des3 -out root.pem 4096
#openssl req -new -x509 -sha256  -key root.pem -out root.crt -days 3650  -subj "/C=ES/ST=Galicia/L=Vigo/O=ACME/OU=ACME Head Office/CN=127.0.0.1"

#openssl dsaparam -out dsaparam.pem 4096
#openssl gendsa -des3 -out root.pem dsaparam.pem
#openssl req -new -x509 -sha256  -key root.pem -out root.crt -days 3650  -subj "/C=ES/ST=Galicia/L=Vigo/O=ACME/OU=ACME Head Office/CN=127.0.0.1"

openssl req -x509 -newkey rsa:4096 -keyout root.pem -out root.crt -sha256 -days 3650 -nodes -subj "/C=ES/ST=Galicia/L=Vigo/O=ACME/OU=ACME Head Office/CN=127.0.0.1"

##############################################################################################################

openssl req -x509 -newkey rsa:4096 -keyout client.pem -out client.pem -sha256 -days 3650 -nodes -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=127.0.0.1"

openssl req -x509 -newkey rsa:4096 -keyout server.pem -out server.pem -sha256 -days 3650 -nodes -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=127.0.0.1"

