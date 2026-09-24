# GPU over vsock — end-to-end witness (tinylabscom/mvm#3567).
#
# Boots real microVMs on a GPU-less host: the per-VM host endpoint answers
# through the deterministic stub backend, so no GPU is required anywhere
# (ADR-053). The scenarios use the persistent machine flow because a
# transient run deletes its state dir on exit — the positive witness
# asserts on the per-VM gpu-endpoint.log after the guest program ran, and
# the negative one proves the state dir carries no endpoint at all.

Feature: GPU over vsock — end-to-end witness

@live @gpu_e2e
Scenario: a --gpu launch remotes CUDA driver and NVML calls to the host endpoint
  Given a gpu probe staging dir
  When I run mvmctl in an isolated live home with a gpu staging mount and "machine create bdd-gpu-witness --image python:3.12 --gpu"
  Then the command exits with code 0
  When I run mvmctl in an isolated live home with a gpu staging mount and "machine volume mount bdd-gpu-witness --volume gpu-shims --host @STAGING@ --guest /data/shims"
  Then the command exits with code 0
  When I run mvmctl in an isolated live home with "machine start bdd-gpu-witness"
  Then the command exits with code 0
  When I run mvmctl in an isolated live home with "machine exec bdd-gpu-witness -- /data/shims/gpu_guest_probe calls /data/shims"
  Then the command exits with code 0
  And the output contains "CUDA_DRIVER_OK"
  And the output contains "NVML_OK"
  And the output contains "stub"
  And the gpu endpoint log for vm bdd-gpu-witness records the probe calls
  When I run mvmctl in an isolated live home with "machine stop bdd-gpu-witness --yes"
  Then the command exits with code 0

@live @gpu_e2e
Scenario: a launch without --gpu refuses the GPU channel
  Given a gpu probe staging dir
  When I run mvmctl in an isolated live home with a gpu staging mount and "machine create bdd-gpu-negative --image python:3.12"
  Then the command exits with code 0
  When I run mvmctl in an isolated live home with a gpu staging mount and "machine volume mount bdd-gpu-negative --volume gpu-shims --host @STAGING@ --guest /data/shims"
  Then the command exits with code 0
  When I run mvmctl in an isolated live home with "machine start bdd-gpu-negative"
  Then the command exits with code 0
  When I run mvmctl in an isolated live home with "machine exec bdd-gpu-negative -- /data/shims/gpu_guest_probe dial"
  Then the command exits with code 3
  And the output contains "CONNECT_REFUSED"
  And the vm bdd-gpu-negative state dir has no gpu endpoint
  When I run mvmctl in an isolated live home with "machine stop bdd-gpu-negative --yes"
  Then the command exits with code 0
