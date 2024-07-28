#!/bin/bash

# This script copied from https://github.com/emarsden/dash-mpd-cli/blob/main/tests/create-certs.sh

# ----------------------------------------------------------------------------------------------
# Copyright (c) 2022-2024 Eric Marsden

# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
# associated documentation files (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge, publish, distribute,
# sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all copies or substantial
# portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
# NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
# OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
# ----------------------------------------------------------------------------------------------


# Create the certificates necessary for our tests:
#   - a root certificate authority
#   - a server running on localhost
#   - a client making authenticated requests to the server
#
# We generate these with openssl, but could try using the rcgen crate.
#
# To dump the content of a certificate, openssl x509 -in cert.csr -text

# we don't need passphrase
# openssl genrsa -aes256 -out root-CA.key 4096
# openssl genrsa -aes256 -out localhost-cert.key 4096
# openssl genrsa -aes256 -out client-cert.key 4096

openssl genrsa -out root-CA.key 4096
openssl genrsa -out localhost-cert.key 4096
openssl genrsa -out client-cert.key 4096


# create the certificate for the root Certificate Authority
openssl req -x509 -new -nodes \
   -sha512 -days 1000 \
   -subj "/C=FR/L=Toulouse/O=Test" \
   -addext "basicConstraints=critical,CA:true,pathlen:0" \
   -addext "keyUsage=critical,keyCertSign,cRLSign" \
   -key root-CA.key \
   -out root-CA.crt

# Create the certificate for the server on localhost. Note that rustls is finicky, requiring the
# subjectAltName field to be present.
openssl req -new -sha512 \
   -subj "/C=FR/L=Toulouse/O=Test/CN=localhost" \
   -addext 'subjectAltName=DNS:localhost' \
   -addext 'basicConstraints=critical,CA:FALSE' \
   -addext 'extendedKeyUsage=serverAuth' \
   -key localhost-cert.key \
   -out localhost-cert.csr
openssl x509 -req \
   -CAcreateserial -days 1000 -sha512 -copy_extensions copy \
   -in localhost-cert.csr \
   -CA root-CA.crt \
   -CAkey root-CA.key \
   -out localhost-cert.crt

# create the certificate for the client
openssl req -new -sha512 -nodes \
   -subj "/C=FR/L=Toulouse/O=Test/CN=local-test-client" \
   -addext "basicConstraints=critical,CA:false" \
   -addext "extendedKeyUsage=clientAuth" \
   -key client-cert.key \
   -out client-cert.csr
openssl x509 -req \
   -CAcreateserial -days 1000 -sha512 -copy_extensions copy \
   -CA root-CA.crt \
   -CAkey root-CA.key \
   -in client-cert.csr \
   -out client-cert.crt
# The client_id is a PEM encoded private key and at least one PEM encoded certificate.
cat client-cert.key client-cert.crt > client-id.pem


# For this test setup, we don't need to keep the key for the root CA nor the signing requests.
# Keep all the certificates and keys in the fixtures/ directory.
rm root-CA.key localhost-cert.csr client-cert.csr
mv root-CA.crt localhost-cert.key localhost-cert.crt client-cert.key client-cert.crt fixtures
mv client-id.pem fixtures
mv root-CA.srl fixtures
