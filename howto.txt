# how to make a DSA key

openssl dsaparam -out dsaparam.pem 2048
openssl gendsa -des3 -out privkey.pem dsaparam.pem

# How to makea RSA key
openssl genrsa -des3 -out privkey.pem 2048
openssl genrsa -aes128 -out privkey.pem 2048

# extract public part of key
openssl rsa -in fd.key -pubout -out fd-public.key


# generate Certificate Request and check it
openssl req -new -key privkey.pem  -out cacert.csr
openssl req -text -in cacert.csr -noout

# sign the certificate request ourseleves
openssl x509 -req -days 365 -in cacert.csr -signkey privkey.pem -out cacert.crt

# in one step how to make a certificate (self signed)
openssl req -new -x509 -key privkey.pem -out cacert.crt -days 1095

# verify
openssl verify cacert.crt

# display
openssl x509 -text -in cacert.crt
