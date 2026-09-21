# Kubernetes in a single microVM

One microVM boots a complete single-node Kubernetes cluster (k3s). The
cluster is a disposable, fork-able artifact: control plane and container
runtime together inside one guest that owns its kernel — no shared host
kernel, no privileged-container workarounds.

## Why a microVM

The kubelet expects to own a kernel: cgroups, filesystem mounts, netfilter.
A container hands it a kernel it does not own; a microVM hands it a real one.
The hypervisor — not a container runtime — is the boundary, which is why
k3s's embedded containerd can run containers with full capabilities against
the guest kernel.

## How it maps onto mvm

| Requirement | How it is satisfied |
|---|---|
| kubelet needs `/dev/kmsg` (1:11) | Hard kubelet requirement; allow-listed in the OCI device unpack list (`mvm-fs`) and created by devtmpfs in the guest. |
| Rootless workload | mvm guest code never runs as root (uid 901 + no-root gate), so k3s runs with `k3s server --rootless` (RootlessKit, user namespaces). |
| No guest NIC | The microVM has no NIC and no TAP/TUN; every host-bound byte leaves over the vsock. The guest egress client runs a SOCKS5/CONNECT proxy on guest loopback (`127.0.0.1:1080`) and tunnels admitted host:port flows to the host. Image pulls and pod egress are wired through that proxy; host ingress exists only at pre-declared `--port` forwards. Cluster-internal traffic (apiserver, pods, services) is ordinary in-guest networking and needs no NIC. |
| Writable cluster state | Sized `:rw` ext4 disk volume attached at `/data`; k3s `--data-dir=/data/k3s`. The rootfs stays read-only. |
| No nested runtime work | k3s embeds containerd; containers run against the guest kernel. |

Plan: `specs/plans/2026-09-20-kubernetes-in-microvm.md`. The guest template
is tracked in the template registry (`tinylabscom/mvm-templates#1`) and the
workload-kernel audit in the image train (`tinylabscom/mvm-images#9`);
runtime tracking is `tinylabscom/mvm#3554`.

## Run (once the guest image is published)

```sh
# Boot the cluster; the data disk holds cluster state across reboots.
mvmctl machine run -d --name k8s --flake .   --mount ./k3s-data:/data:20G:rw   --allow-host registry-1.docker.io:443

# Drive it over the dev-tier exec channel.
mvmctl machine exec k8s -- kubectl get nodes
mvmctl machine exec k8s -- kubectl apply -f deployment.yaml

# Tear the whole cluster down.
mvmctl machine stop k8s --yes
```

Reach a workload from the host by declaring a signed ingress port at launch
(`--port 8080:80`) — the cluster has no NodePort-on-a-NIC semantics to
publish.

Driving verbs (`machine exec` and friends) are DevOnly: this is a dev/test
capability, refused by prod admission. Sizing starts at 4 vCPU / 4 GiB;
container image storage is what consumes the `/data` disk.
