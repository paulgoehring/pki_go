FROM ghcr.io/edgelesssys/ego-dev AS build
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl dnsutils iptables jq nghttp2

RUN git clone https://github.com/paulgoehring/pki_go/ /pki_go
WORKDIR /pki_go/pki/server
RUN ego install sgx-driver 
RUN ego-go build
RUN ego sign server


FROM ghcr.io/edgelesssys/ego-deploy AS deploy

ARG ERT_VERSION="0.4.1"
ARG ERT_DEB=edgelessrt_${ERT_VERSION}_amd64_ubuntu-20.04.deb
RUN wget https://github.com/edgelesssys/edgelessrt/releases/download/v${ERT_VERSION}/$ERT_DEB && \
    apt-get update && apt install -y ./$ERT_DEB build-essential
ENV PATH=/opt/edgelessrt/bin:$PATH

LABEL description="Pki Server"
COPY --from=build /pki_go/pki/server /server/


ENV AZDCAP_DEBUG_LOG_LEVEL=error
ENV EDG_MARBLE_TYPE=pkis
ENTRYPOINT [ "sh", "-c", "ego uniqueid /server/server && ego marblerun /server/server" ]
# ENTRYPOINT ["ego", "marblerun", "client/client"]