# nsm-nse-generic

An NSE for Vlan forwarder in NSM next-gen.

This NSE was created for test and experimental purposes.

For now it only provides IPAM functionality.

Dual-stack is not yet supported.


## Build image

```
./build.sh image
# Upload to xcluster local registry
images lreg_upload --strip-host registry.nordix.org/cloud-native/nsm/nse-vlan:latest
```

