# The workload for the mission demo's production-profile run: a deterministic,
# scripted "planted compromise", not a model. The base is pinned by digest so
# the image's bytes do not move under a signature.
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
COPY mission-node.sh /usr/local/bin/mission-node
# A production run executes the image's own command; nothing can be passed
# after `--`.
CMD ["/usr/local/bin/mission-node"]
