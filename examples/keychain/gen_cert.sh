if [ $# -ne 1 ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

DOMAIN=$1

# Create directory for the domain
mkdir -p ${DOMAIN}

# gen server private key
openssl ecparam -name secp384r1 -genkey -noout -out ${DOMAIN}/${DOMAIN}-ECC.key
# create csr 
openssl req -new -key ${DOMAIN}/${DOMAIN}-ECC.key -out ${DOMAIN}/${DOMAIN}.csr -subj "/C=CN/ST=Beijing/L=Beijing/O=GenMeta/CN=${DOMAIN}"
# gen server cert with v3
cat <<EOT > ${DOMAIN}/openssl.cnf
[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${DOMAIN}
EOT

openssl x509 -req \
  -extfile ${DOMAIN}/openssl.cnf -extensions v3_req \
  -in ${DOMAIN}/${DOMAIN}.csr \
  -CA root/rootCA-ECC.crt -CAkey root/rootCA-ECC.key -CAcreateserial \
  -out ${DOMAIN}/${DOMAIN}-ECC.crt -days 365 -sha384

# view info in ${DOMAIN}-ECC.crt
openssl x509 -in ${DOMAIN}/${DOMAIN}-ECC.crt -text -noout