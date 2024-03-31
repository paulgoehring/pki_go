FROM golang:1.17 AS build

RUN git clone https://github.com/paulgoehring/pki_go/ /pki_go
WORKDIR /pki_go/pki/root_server

RUN go build -o root_server

FROM ubuntu:20.04

WORKDIR /root

RUN apt-get update && apt-get install -y wget && rm -rf /var/lib/apt/lists/*

# Download and install marblerun
RUN wget https://github.com/edgelesssys/marblerun/releases/latest/download/marblerun-ubuntu-20.04 && \
    chmod +x marblerun-ubuntu-20.04 && \
    mv marblerun-ubuntu-20.04 /usr/local/bin/marblerun

RUN apt-get update && \
    apt-get install -y wget && \
    mkdir -p /etc/apt/keyrings && \
    wget -qO- https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | tee /etc/apt/keyrings/intel-sgx-keyring.asc > /dev/null && \
    echo "deb [signed-by=/etc/apt/keyrings/intel-sgx-keyring.asc arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main" | tee /etc/apt/sources.list.d/intel-sgx.list && \
    apt-get update && \
    apt-get install -y libsgx-dcap-default-qpl

RUN apt-get update && \
    apt-get install -y gnupg && \
    echo "deb [arch=amd64] https://packages.microsoft.com/ubuntu/20.04/prod focal main" | tee /etc/apt/sources.list.d/msprod.list && \
    wget -qO - https://packages.microsoft.com/keys/microsoft.asc | apt-key add - && \
    apt-get update && \
    apt-get install -y az-dcap-client
# Clean up
RUN rm -rf /var/lib/apt/lists/*


COPY --from=build /pki_go/pki/root_server/root_server .
COPY --from=build manifest.json .
COPY --from=build /pki_go/pki/root_server/start.sh .
RUN chmod +x start.sh

#CMD /bin/sh -c "marblerun manifest verify manifest.json localhost:4433 --coordinator-cert marblerunCA.crt && ./root_server"
CMD ["/root/start.sh"]
