# Test kernel to vlan connection

This example shows that NSC and NSE on the different nodes could find and work with each other.

NSCs are using the `kernel` mechanism to connect to its local forwarder.
Forwarders are using the `vlan` remote mechanism towards NSE.

## Requires

Make sure that you have completed steps from [basic](deployments-k8s/examples/basic) setup.

## Run

Create test namespace:

```bash
NAMESPACE=($(kubectl create -f https://raw.githubusercontent.com/networkservicemesh/deployments-k8s/9f03e7dfa191a20ce481b6af789ccfc26865ab78/examples/use-cases/namespace.yaml)[0])
NAMESPACE=${NAMESPACE:10}
```

Create customization file:

```bash
cat > kustomization.yaml <<EOF
---
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

namespace: ${NAMESPACE}

resources:
- nsc-vlan.yaml

EOF
```

Deploy NSC and NSE:
```bash
kubectl apply -f nse-new-vlan.yaml -n nsm-system
kubectl apply -k .
```

Wait for applications ready:
```bash
kubectl wait --for=condition=ready --timeout=1m pod -l app=nsc -n ${NAMESPACE}
```
```bash
kubectl wait --for=condition=ready --timeout=1m pod -l app=nse -n nsm-system
```

Find NSC and NSE pods by labels:
```bash
NSCS=($(kubectl get pods -l app=nsc -n ${NAMESPACE} --template '{{range .items}}{{.metadata.name}}{{"\n"}}{{end}}'))
```

Ping each NSC address from each NSC:
```bash
kubectl exec ${NSCS[0]} -n ${NAMESPACE} -- ping -c 4 172.10.0.1
kubectl exec ${NSCS[1]} -n ${NAMESPACE} -- ping -c 4 172.10.0.1
kubectl exec ${NSCS[0]} -n ${NAMESPACE} -- ping -c 4 172.10.0.2
kubectl exec ${NSCS[1]} -n ${NAMESPACE} -- ping -c 4 172.10.0.2
```

## Cleanup

Delete ns:
```bash
kubectl delete ns ${NAMESPACE}
```