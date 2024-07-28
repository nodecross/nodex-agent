FROM rust:slim-bullseye

RUN apt-get update && apt-get install -y openssl libssl-dev pkg-config

COPY ./fixtures/client-cert.crt /usr/local/share/ca-certificates/

RUN update-ca-certificates
