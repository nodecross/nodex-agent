<p align="center">
  <img src="images/unid_logo_github.svg" alt="logo" width="160" />
</p>

<h1 align="center">
  UNiD
</h1>

<p align="center">
  <a href="https://github.com/getunid/unid/actions/workflows/release-pipeline.yml" target="_blank">
    <img src="https://github.com/getunid/unid/actions/workflows/release-pipeline.yml/badge.svg?branch=main" alt="Unit Test" />
  </a>
  <a href="https://coveralls.io/github/getunid/unid" target="_blank">
    <img src="https://coveralls.io/repos/github/getunid/unid/badge.svg" alt="Coverage Status" />
  </a>
  <a href="https://crates.io/crates/unid" target="_blank">
    <img src="https://img.shields.io/crates/v/unid.svg" alt="unid" />
  </a>
  <a href="https://github.com/semantic-release/semantic-release" target="_blank">
    <img src="https://img.shields.io/badge/semantic--release-rust-B7410E?logo=semantic-release" alt="Sematic-Release" />
  </a>
  <br />
  Automate device security provisioning with edge intelligence
</p>


## Features

- Abstract the dev complexity of edge security
- Fully automated device provisioning
- End-to-end authenticated and encrypted communications
- Security lifecycle
- Overlay routing
- Cloud add-ons for real-time data flow and processing
- Developer-first

## Introduction

Hardware Root of Trust is the security foundation for an SoC, other semiconductor device or electronic system. The RoT contains the keys for cryptographic functions and is usually a part of the secure boot process providing the foundation for the software chain of trust. _UNiD_ is a set of libraries written by Rust that can leverage the RoT and decentralized identity technology to autonomously generate key pairs, register the credentials on a decentralized PKI, and build end-to-end secure channel by the TLS handshake protocol. This capabilities reduce the development cost of device security, increase flexibilities, and facilitates real-time data flow and processing.

<p align="center">
  <img src="images/e2e_secure_channel.svg" alt="e2e secure channel" width="80%" />
</p>

## Overview

By abstracting every device and cloud as globally unique endpoints and building an E2E secure channel, each endpoint can send encrypted messages regardless of the network topology or routing hops.

<p align="center">
  <img src="images/UNiD_BB.svg" alt="UNiD Building Blocks" />
</p>

## Quick Start

[TBD]

## Developer's Document

[TBD]

## Changelog

[CHANGELOG](CHANGELOG.md)


## License

[Apache License 2.0](LICENSE)
