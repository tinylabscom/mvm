"""Print the Python SDK's public surface as sorted JSON.

Twin of `typescript_surface.mjs`. The scenario compares the two so the two
SDKs cannot drift apart without someone deciding they should.
"""

import json

import mvm

print(json.dumps(sorted(mvm.__all__)))
