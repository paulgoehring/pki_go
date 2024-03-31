
## install azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

az login

## set up cluster with confidential computing nodes


az group create --name paulClusterGroup --location eastus

az aks create -g paulClusterGroup --name paulCluster --generate-ssh-keys --enable-addons confcom --enable-sgxquotehelper

funktioniert auch ohne : (az aks addon update --addon confcom --name " YourAKSClusterName " --resource-group "YourResourceGroup " --enable-sgxquotehelper) this time not ? 

az aks nodepool add --cluster-name paulCluster --name confcompool1 --resource-group paulClusterGroup --node-vm-size Standard_DC2s_v2 --node-count 2

## install and set up kubectl locally
curl -LO "https://dl.k8s.io/release/v1.25.11/bin/linux/amd64/kubectl"

sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

az aks get-credentials --resource-group paulClusterGroup --name paulCluster  // to connect with cluster

# install and set up marblerun
# needs working dcap setup, azure dcap or set up Intel PCCS locally
kubectl version --short 

sudo wget -O /usr/local/bin/marblerun https://github.com/edgelesssys/marblerun/releases/latest/download/marblerun
sudo chmod +x /usr/local/bin/marblerun

marblerun

marblerun precheck

marblerun install

marblerun check

kubectl -n marblerun port-forward svc/coordinator-client-api 4433:4433 --address localhost >/dev/null &
export MARBLERUN=localhost:4433

marblerun certificate root $MARBLERUN -o marblerun.crt

## view root certificate

View certificate: openssl x509 -in marblerun.crt -text -noout
