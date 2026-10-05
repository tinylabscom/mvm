This immutable fixture is the `runtime/python@1.1.0` pack signed by the
`mvm-templates` publish workflow on the `feat/3716-python-image-pack` branch.
The manifest, payload files, and Sigstore bundle are copied byte-for-byte
from the published layout at commit `66afff3`. Tests pin that workflow's
branch identity explicitly; production's default publisher trust remains
restricted to its main-branch identity.
