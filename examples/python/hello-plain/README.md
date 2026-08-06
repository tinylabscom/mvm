# hello-plain (Python)

A plain Python script with no `mvm` SDK dependency. Use this to sanity-check
`mvmctl machine run` with a Python OCI image and a host mount.

## Run directly inside a Python VM

```sh
cargo run -- machine run --image python:3.12 \
  --mount "$PWD/examples/python/hello-plain/:/work:ro" \
  -- python /work/app.py
```

Expected output:

```
hello from mvm python
```

## Add a pip dependency

To install a package at runtime (network required):

```sh
cargo run -- machine run --image python:3.12 \
  --allow-host pypi.org:443 \
  --allow-host files.pythonhosted.org:443 \
  --mount "$PWD/examples/python/hello-plain/:/work:ro" \
  -- sh -c 'python -m pip install --no-cache-dir --target /tmp/python-deps requests && PYTHONPATH=/tmp/python-deps python /work/app.py'
```

For SDK-annotated workloads with declared dependencies, see
`examples/python/hello-app/` and `examples/python/hello-app-with-deps/`.
