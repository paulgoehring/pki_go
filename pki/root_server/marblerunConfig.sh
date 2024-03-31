#!/bin/bash

minikube delete

minikube start --mount --mount-string /dev/sgx:/dev/sgx --memory 6g

kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v1.12.2/cert-manager.yaml

kubectl wait --for=condition=available --timeout=60s -n cert-manager --all deployments

kubectl apply -k https://github.com/intel/intel-device-plugins-for-kubernetes/deployments/sgx_plugin/overlays/epc-register/?ref=v0.27.1

kubectl apply -k https://github.com/intel/intel-device-plugins-for-kubernetes/deployments/sgx_admissionwebhook/overlays/default-with-certmanager/?ref=v0.27.1

marblerun install

marblerun check

kubectl -n marblerun port-forward svc/coordinator-client-api 4433:4433 --address localhost >/dev/null &

kubectl -n marblerun port-forward svc/coordinator-mesh-api 2001:2001 --address localhost >/dev/null &