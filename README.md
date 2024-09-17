<p align="center">
  <img src="images/nodex-logo.svg" alt="NodeX Logo" width="130" />
</p>

<h2 align="center">
  NodeX - E2E Secure Messaging Platform<br />
  <a href="https://github.com/nodecross/nodex/actions/workflows/release.yml">
    <img src="https://github.com/nodecross/nodex/actions/workflows/release.yml/badge.svg?branch=main" alt="Release Pipeline" />
  </a>
  <a href="https://github.com/semantic-release/semantic-release">
    <img src="https://img.shields.io/badge/semantic--release-rust-B7410E?logo=semantic-release" alt="Semantic Release" />
  </a>
</h2>

NodeX is an open-source toolkit for building end-to-end secure messaging between all devices including IoT, micro services, and on-premise servers, using features of [decentralized identifiers (DIDs)](https://www.w3.org/TR/did-core/) as a basis of security and privacy. Build atop [DIDComm messaging protocol](https://github.com/decentralized-identity/didcomm-messaging) which works over any transports, it makes end-to-end messaging reliable, secure, and easy.

This repo where we develop libraries to be installed into your devices. It enables device's IDs and keys management with root of trust (RoT), automated provisioning, mutual authentication, and end-to-end secure messaging across network boundary.

[Explore NodeX Docs](https://docs.nodecross.io)

## Features

- Device's IDs and keys management with RoT
- Automated provisioning without centralized servers and certificate authorities and intermediaries
- Mutual authentication and end-to-end secure messaging while ensuring confidentiality, integrity, and authenticity
- Attribute based access control and dynamic policy management
- Rust library with multiple language extensions for python and nodejs
- Mutiple OS support for Linux kernel x86(32bit) & x86-64(64bit), FreeRTOS ARM Cortex-M33(32bit)
- RoT extensions for TPM, ARM TrustZone, and Renesas SCE

## Install

- [Build Guide](https://docs.nodecross.io/installation/00-overview.html)

## Developer's Document

- NodeX Official Website<br />
  https://nodecross.io

- NodeX Developers Portal<br />
  https://docs.nodecross.io

## Contribution

First off, thank you for considering making contributions. It's people like you that make NodeX better. There are many ways in which you can participate in the project, for example:

- File a bug report. Be sure to include information like what version of NodeX you are using, what your operating system and CPU is, and steps to recreate the bug.
- Suggest a new feature.

## Security

[SECURITY](SECURITY.md)

## License

[Apache License 2.0](LICENSE)
