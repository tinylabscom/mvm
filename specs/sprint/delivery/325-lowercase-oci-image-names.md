# Lowercase OCI image names

OCI image registry and repository components now normalize ASCII capitals to
lowercase before validation, so inputs such as `Alpine` and
`GHCR.IO/Acme/Widget:v1` resolve to their canonical lowercase repositories.
Case-sensitive tags remain unchanged, and digest validation remains strict.
Unit and hermetic BDD coverage pin both the normalization and its boundaries.
