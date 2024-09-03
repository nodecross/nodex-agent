FROM ubuntu:22.04

ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    DEBIAN_FRONTEND=noninteractive


RUN apt-get update && apt-get install -y \
    curl \
    git \
    build-essential \
    ruby \
    ruby-dev \
    sudo \
    chrpath \
    file \
    systemctl \
    vim \
    sudo \
    podman \
    dmidecode \
    && rm -rf /var/lib/apt/lists/*
RUN gem install bundler

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN cargo install cross

WORKDIR /nodex
COPY omnibus /nodex/omnibus
RUN cd /nodex/omnibus && bundle install --binstubs

CMD ["/bin/bash"]
