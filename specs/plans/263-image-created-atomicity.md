# Atomic image-lineage publication

Issue: #1833

Status: COMPLETE

## Scope

Prepare the serialized image-lineage node before emitting `image.created`, then
publish the prepared file atomically only after the signed audit entry succeeds.
An audit or staging failure must leave no visible node or phantom creation entry.

## Delivery checklist

- [x] Add a staged image-node publication API with RAII cleanup for abandoned
      temporary files.
- [x] Move the build recorder to stage, audit, then atomically publish.
- [x] Add store and recorder tests for uncommitted-stage cleanup and staging
      failure before audit emission.
- [x] Run formatting, workspace check, tests, and clippy gates.
- [x] Publish the verified branch as pull request #1846.

Pull request #1846 is open for review.
