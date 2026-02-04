# Create root directory
mkdir -p root

# gen root key
openssl ecparam -name secp384r1 -genkey -noout -out root/rootCA-ECC.key
# gen self-signed cert
openssl req -new -x509 -days 3650 -key root/rootCA-ECC.key -sha384 -out root/rootCA-ECC.crt -subj "/C=CN/ST=Beijing/L=Beijing/O=GenMeta/CN=RootCA"