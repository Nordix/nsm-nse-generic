# nsm-nse-generic

A generic NSE for NSM next-gen.

This NSE was created for educational and experimental purposes.

For now it only provides IPAM functionality. Both p-2-p and full L2
subnet is supported for ipv4 and ipv6.

Dual-stack is not yet supported since the way to implement dual-stack
is unclear.

The `nse-generic.yaml` file configures the nse-generic to be
compatible with the
[cmd-nse-icmp-responder](https://github.com/networkservicemesh/cmd-nse-icmp-responder).


## Build image

```
./build.sh image
# Upload to xcluster local registry
images lreg_upload --strip-host registry.nordix.org/cloud-native/nsm/nse-generic:latest
```

