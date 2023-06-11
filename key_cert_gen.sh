#!/bin/sh
# for windows use winpty, for linux remove winpty
winpty openssl genrsa -aes256 -out priv.pem 4096
cat priv.pem
winpty openssl rsa -text -in priv.pem
winpty openssl rsa -in priv.pem -pubout -out pub.pem

winpty openssl req -new -key priv.pem -out cert.csr
winpty openssl req -text -in cert.csr -noout
winpty openssl x509 -req -days 365 -in cert.csr -signkey priv.pem -out cert.crt