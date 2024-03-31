## Docker

## baue den Container

docker build -t clientpki .

## starte den Container

docker run -it --network host --device /dev/sgx_enclave --device /dev/sgx_provision -v /dev/sgx:/dev/sgx -v /etc/sgx_default_qcnl.conf:/etc/sgx_default_qcnl.conf clientpki


## standalone

git clone https://github.com/paulgoehring/pki_go/

cd pki/client

ego-go build
ego sign client
EDG_MARBLE_TYPE=pkic ego marblerun client