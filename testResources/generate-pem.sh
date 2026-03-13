#!/bin/sh

set -eux

# Configurable parameters (override via environment variables)
PASSWORD="${PASSWORD:-certkit}"
SUBJECT_CA="${SUBJECT_CA:-/C=US/ST=CA/L=San Jose/O=CertKit/OU=RootCA}"
SUBJECT_CLIENT="${SUBJECT_CLIENT:-/C=US/ST=CA/L=San Jose/O=CertKit/OU=Server/CN=Test User}"
PKCS8_V1_ALGO="${PKCS8_V1_ALGO:-PBE-SHA1-3DES}"

# --- CA keys (PKCS#8) ---
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out rsa.ca.key
openssl genpkey -genparam -algorithm DSA -pkeyopt dsa_paramgen_bits:2048 -out dsaparam.pem
openssl genpkey -paramfile dsaparam.pem -out dsa.ca.key
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out ec.ca.key

# --- CA self-signed certificates ---
openssl req -new -x509 -days 9999 -subj "$SUBJECT_CA" -key rsa.ca.key -out rsa.ca.crt
openssl req -new -x509 -days 9999 -subj "$SUBJECT_CA" -key dsa.ca.key -out dsa.ca.crt
openssl req -new -x509 -days 9999 -subj "$SUBJECT_CA" -key ec.ca.key -out ec.ca.crt

# --- Client keys: PKCS#8 (genpkey default) and traditional/PKCS#1 ---
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out rsa.client.pkcs8.key
openssl pkey -traditional -in rsa.client.pkcs8.key -out rsa.client.pkcs1.key

openssl genpkey -paramfile dsaparam.pem -out dsa.client.pkcs8.key
openssl pkey -traditional -in dsa.client.pkcs8.key -out dsa.client.pkcs1.key

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out ec.client.pkcs8.key
openssl pkey -traditional -in ec.client.pkcs8.key -out ec.client.pkcs1.key

# --- Encrypted PKCS#8 client keys ---
openssl pkcs8 -topk8 -v1 "$PKCS8_V1_ALGO" -inform pem -outform pem -passout pass:"$PASSWORD" -in rsa.client.pkcs8.key -out rsa.client.pkcs8.key.encrypted
openssl pkcs8 -topk8 -v1 "$PKCS8_V1_ALGO" -inform pem -outform pem -passout pass:"$PASSWORD" -in dsa.client.pkcs8.key -out dsa.client.pkcs8.key.encrypted
openssl pkcs8 -topk8 -v1 "$PKCS8_V1_ALGO" -inform pem -outform pem -passout pass:"$PASSWORD" -in ec.client.pkcs8.key -out ec.client.pkcs8.key.encrypted

# --- Public key in PKCS#1 format (only RSA supports this format) ---
openssl rsa -in rsa.client.pkcs8.key -RSAPublicKey_out -out rsa.client.pkcs1.pub

# --- Public keys in standard X.509/PKCS#8 format (works for all key types) ---
openssl pkey -pubout -in rsa.client.pkcs8.key -out rsa.client.pkcs8.pub
openssl pkey -pubout -in dsa.client.pkcs8.key -out dsa.client.pkcs8.pub
openssl pkey -pubout -in ec.client.pkcs8.key -out ec.client.pkcs8.pub

# --- Client certificate signing requests ---
openssl req -new -subj "$SUBJECT_CLIENT" -passin pass:"$PASSWORD" -key rsa.client.pkcs8.key -out rsa.client.csr
openssl req -new -subj "$SUBJECT_CLIENT" -passin pass:"$PASSWORD" -key dsa.client.pkcs8.key -out dsa.client.csr
openssl req -new -subj "$SUBJECT_CLIENT" -passin pass:"$PASSWORD" -key ec.client.pkcs8.key -out ec.client.csr

# --- Client certificates (signed by corresponding CA) ---
openssl x509 -req -days 9999 -set_serial 01 -CA rsa.ca.crt -CAkey rsa.ca.key -in rsa.client.csr -out rsa.client.crt
openssl x509 -req -days 9999 -set_serial 01 -CA dsa.ca.crt -CAkey dsa.ca.key -in dsa.client.csr -out dsa.client.crt
openssl x509 -req -days 9999 -set_serial 01 -CA ec.ca.crt -CAkey ec.ca.key -in ec.client.csr -out ec.client.crt

# --- Composite PEM bundles: CA cert + client cert + client key ---
cat rsa.ca.crt rsa.client.crt rsa.client.pkcs1.key > rsa.client.pkcs1.pem
cat dsa.ca.crt dsa.client.crt dsa.client.pkcs1.key > dsa.client.pkcs1.pem
cat ec.ca.crt ec.client.crt ec.client.pkcs1.key > ec.client.pkcs1.pem

cat rsa.ca.crt rsa.client.crt rsa.client.pkcs8.key.encrypted > rsa.client.pkcs8.pem.encrypted
cat dsa.ca.crt dsa.client.crt dsa.client.pkcs8.key.encrypted > dsa.client.pkcs8.pem.encrypted
cat ec.ca.crt ec.client.crt ec.client.pkcs8.key.encrypted > ec.client.pkcs8.pem.encrypted

# --- Cleanup intermediate files ---
rm rsa.ca.key dsa.ca.key ec.ca.key dsaparam.pem
rm rsa.client.csr dsa.client.csr ec.client.csr