"""Print the Python SDK's public surface as sorted JSON.

Twin of `typescript_surface.mjs`. The scenario compares the two so the two
SDKs cannot drift apart without someone deciding they should.
"""

import json
from dataclasses import FrozenInstanceError, fields, is_dataclass

import mvm

details_type = mvm.RecoveryRequiredDetails
assert is_dataclass(details_type)
assert details_type.__dataclass_params__.frozen
assert [field.name for field in fields(details_type)] == [
    "machine_id",
    "plan_id",
    "reason",
]
assert all(field.kw_only for field in fields(details_type))
details = details_type(machine_id="machine", plan_id="plan", reason="fixture")
try:
    details_type("machine", "plan", "fixture")
except TypeError:
    pass
else:
    raise AssertionError("recovery details must reject positional construction")
try:
    details.machine_id = "changed"
except FrozenInstanceError:
    pass
else:
    raise AssertionError("recovery details must reject field mutation")
assert details.machine_id == "machine"

error = mvm.MachineRecoveryRequiredError("surface fixture")
assert isinstance(error, mvm.HostLibraryError)
assert str(error) == "surface fixture"
assert not hasattr(error, "details"), "the normal constructor must not invent details"

print(json.dumps(sorted(mvm.__all__)))
