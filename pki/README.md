# Installiere Voraussetzungen

# Minikube

curl -Lo minikube https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64 \
  && chmod +x minikube

sudo cp minikube /usr/local/bin && rm minikube

# Marblerun CLI + quote provider library
https://docs.edgeless.systems/marblerun/getting-started/installation

wget https://github.com/edgelesssys/marblerun/releases/latest/download/marblerun-ubuntu-20.04

sudo install marblerun-ubuntu-20.04 /usr/local/bin/marblerun

# azure dcap
echo "deb [arch=amd64] https://packages.microsoft.com/ubuntu/20.04/prod focal main" | sudo tee /etc/apt/sources.list.d/msprod.list
wget -qO - https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -

sudo apt-get update
sudo apt-get install -y az-dcap-client

# kubectl?
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl.sha256"
echo "$(cat kubectl.sha256)  kubectl" | sha256sum --check
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
kubectl version --client


# docker?
for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do sudo apt-get remove $pkg; done
sudo apt-get update
sudo apt-get install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources:
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo docker run hello-world

sudo groupadd docker
sudo usermod -aG docker ${USER}
# log out or following if not working
su -s ${USER}
docker run hello-world

Intel SGX, evtl edgelessrt? -> nicht benötigt
## etc/sgx_default_qcnl.conf -> hier PCCS Server Endpuntk definieren


# Bereite Minikube Umgebung vor

minikube delete

minikube start --mount --mount-string /dev/sgx:/dev/sgx --memory 6g

kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v1.12.2/cert-manager.yaml

kubectl wait --for=condition=available --timeout=60s -n cert-manager --all deployments

kubectl apply -k https://github.com/intel/intel-device-plugins-for-kubernetes/deployments/sgx_plugin/overlays/epc-register/?ref=v0.27.1

kubectl apply -k https://github.com/intel/intel-device-plugins-for-kubernetes/deployments/sgx_admissionwebhook/overlays/default-with-certmanager/?ref=v0.27.1


git clone https://github.com/paulgoehring/pki_go/

# Bereite Marblerun vor

marblerun install -> hier kann dann server endpunkt für marblerun definiert werden

marblerun check

kubectl -n marblerun port-forward svc/coordinator-client-api 4433:4433 --address localhost >/dev/null &

export MARBLERUN=localhost:4433

kubectl -n marblerun port-forward svc/coordinator-mesh-api 2001:2001 --address localhost >/dev/null &


marblerun manifest set manifest.json $MARBLERUN 

marblerun manifest verify ../client/manifest.json $MARBLERUN --coordinator-cert marblerunCA.crt


# Starte Anwendungen

docker build -t rootpki .
docker run -it --network host rootpki

docker build -t serverpki .

docker run -it --network host --device /dev/sgx_enclave --device /dev/sgx_provision -v /dev/sgx:/dev/sgx -v /etc/sgx_default_qcnl.conf:/etc/sgx_default_qcnl.conf  serverpki

docker build -t clientpki .

docker run -it --network host --device /dev/sgx_enclave --device /dev/sgx_provision -v /dev/sgx:/dev/sgx -v /etc/sgx_default_qcnl.conf:/etc/sgx_default_qcnl.conf  clientpki