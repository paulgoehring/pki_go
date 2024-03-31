## Docker

## baue den Container

docker build -t serverpki .

## starte den Container

docker run -it --network host --device /dev/sgx_enclave --device /dev/sgx_provision -v /dev/sgx:/dev/sgx -v /etc/sgx_default_qcnl.conf:/etc/sgx_default_qcnl.conf serverpki


## standalone

git clone https://github.com/paulgoehring/pki_go/

cd pki/server

ego-go build
ego sign server
EDG_MARBLE_TYPE=pkis ego marblerun server