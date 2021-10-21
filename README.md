# Intro

This repo contains 'nse-vlan' an NSE application for Network Service Mesh. It provides ipam and vlan configuration context for registered Network Services.

# Usage

`nse-vlan` accept following environment variables:
* NSM_NAME                  Name of the endpoint
* NSM_CONNECT_TO            An URL of registry service to connect to
* NSM_MAX_TOKEN_LIFETIME    Maximum lifetime of tokens
* NSM_CIDR_PREFIX           CIDR Prefix to assign IPs from
* NSM_IPV6_PREFIX           Ipv6 Prefix for dual-stack
* NSM_REGISTER_SERVICE      if true then registers network service on startup
* NSM_LISTEN_ON             tcp:// url to be listen on. It will be used as public to register NSM
* NSM_SERVICES              List of supported services


# Build

## Build cmd binary locally

You can build the locally by executing

```bash
go build ./...
```

## Build Docker container

You can build the docker container by running:

```bash
docker build .
```
