## Installiere Vorraussetzungen

sudo ./installDependencies.sh

Neu einloggen um Docker ohne sudo Verwenden zu können -> test mit docker run hello-world

Wenn PKI-Server und Client nicht im Kubernetes Cluster integriert werden, muss in der Datei \etc\sgx_c

## Definiere Manifest, UniqueID für PKI-Server und PKI-Client wenn Docker Container neu gebaut wird

## Installiere MarbleRun Vorraussetzungen und bereite Minikube Umgebung vor

./marblerunConfig.sh

## baue den Container

docker build -t rootpki .

docker run -it --network host rootpki

## starte den PKI-Server und PKI-Client