# Installiere Voraussetzungen

Minikube

Marblerun CLI

Intel SGX, evtl edgelessrt?
## etc/sgx_default_qcnl.conf -> hier PCCS Server Endpuntk definieren


# Bereite Minikube Umgebung vor

minikube delete

minikube start --mount --mount-string /dev/sgx:/dev/sgx --memory 6g

kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v1.12.2/cert-manager.yaml

kubectl wait --for=condition=available --timeout=60s -n cert-manager --all deployments

kubectl apply -k https://github.com/intel/intel-device-plugins-for-kubernetes/deployments/sgx_plugin/overlays/epc-register/?ref=v0.27.1

kubectl apply -k https://github.com/intel/intel-device-plugins-for-kubernetes/deployments/sgx_admissionwebhook/overlays/default-with-certmanager/?ref=v0.27.1

# Bereite Marblerun vor


marblerun install -> hier kann dann server endpunkt für marblerun definiert werden



marblerun check

kubectl -n marblerun port-forward svc/coordinator-client-api 4433:4433 --address localhost >/dev/null &

export MARBLERUN=localhost:4433

kubectl -n marblerun port-forward svc/coordinator-mesh-api 2001:2001 --address localhost >/dev/null &


marblerun manifest set manifest.json $MARBLERUN 

marblerun manifest verify ../client/manifest.json $MARBLERUN --coordinator-cert marblerunCA.crt


# Starte Anwendungen

docker build -t serverfinal .

docker run -it --network host --device /dev/sgx_enclave --device /dev/sgx_provision -v /dev/sgx:/dev/sgx -v /etc/sgx_default_qcnl.conf:/etc/sgx_default_qcnl.conf  serverfinal

docker build -t clientid .

docker run -it --network host --device /dev/sgx_enclave --device /dev/sgx_provision -v /dev/sgx:/dev/sgx -v /etc/sgx_default_qcnl.conf:/etc/sgx_default_qcnl.conf  clientid