# The workload for the mission demo's production-profile run: a deterministic,
# scripted "planted compromise", not a model. The base is pinned by digest so
# the image's bytes do not move under a signature.
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
# Links the published package to this repository, so it takes the repository's
# visibility and access; without it a package pushed from a workflow is private
# and an anonymous production pull is refused.
LABEL org.opencontainers.image.source="https://github.com/tinylabscom/mvm"
COPY mission-node.sh /usr/local/bin/mission-node
# A production run executes the image's own command; nothing can be passed
# after `--`.
CMD ["/usr/local/bin/mission-node"]
