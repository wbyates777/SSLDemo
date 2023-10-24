#!/bin/sh

# This shell script will generate the certificates needed to run the demo

#
# generate a password protected private key 'root.pem'; could be rsa or dsa
#

#openssl genrsa -aes128 -out root.pem 4096

openssl genrsa -des3 -out root.pem 4096

#openssl dsaparam -out dsaparam.txt 4096
#openssl gendsa -des3 -out root.pem dsaparam.txt



#
# Any of the three following (groups of) commands will generate a valid root.crt 
#

# this assumes we have a root.pem
# generate certificate request and check it
#openssl req -new -key root.pem -out root.csr
#openssl req -text -in root.csr -noout
# sign the certificate request ourseleves
#openssl x509 -req -days 3650 -in root.csr -signkey root.pem -out root.crt

# this assumes we have a root.pem
openssl req -x509 -new -key root.pem -out root.crt -sha256 -days 3650 -nodes -subj "/C=ES/ST=Galicia/L=Vigo/O=ACME/OU=ACME Head Office/CN=127.0.0.1"

# these commands generate a root.pem; don't forget to comment out any genrsa or gendsa commands above
# the -nodes flags disables the password protection
#openssl req -x509 -newkey rsa:4096 -keyout root.pem -out root.crt -sha256 -days 3650 -nodes -subj "/C=ES/ST=Galicia/L=Vigo/O=ACME/OU=ACME Head Office/CN=127.0.0.1"
# or
#openssl req -x509 -newkey dsa:4096 -keyout root.pem -out root.crt -sha256 -days 3650 -nodes -subj "/C=ES/ST=Galicia/L=Vigo/O=ACME/OU=ACME Head Office/CN=127.0.0.1"


# display certificate
openssl x509 -text -in root.crt



##############################################################################################################



openssl req -x509 -newkey rsa:4096 -keyout client.pem -out client.pem -sha256 -days 3650 -nodes -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=127.0.0.1"

openssl req -x509 -newkey rsa:4096 -keyout server.pem -out server.pem -sha256 -days 3650 -nodes -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=127.0.0.1"

