"""Constructor surface tests.

These exist because the suite had no coverage of `addon_use` at all: a
refactor deleted the module-level `_UNRESOLVED_SHA256` it depends on and
all 212 tests still passed, because nothing called it. The cross-language
golden document caught that, which is the right outcome — but a Python
break should fail the Python suite too, without needing the BDD layer.
"""

import pytest

import mvm


class TestAddonUse:
    def test_registry_use_derives_its_url_and_placeholder_hash(self):
        used = mvm.addon_use("postgres", version="16", alias="db")
        assert used.name == "postgres"
        assert used.alias == "db"
        assert used.ref.url == "addons.mvm.io/postgres"
        assert used.ref.version == "16"
        # The unlocked marker: 64 zero hex chars, replaced by `addon lock`.
        assert used.sha256 == "0" * 64

    def test_local_use_keeps_the_path(self):
        used = mvm.addon_use("my-db", path="./addons/my-db")
        assert used.ref.path == "./addons/my-db"
        assert used.sha256 == "0" * 64

    def test_an_explicit_hash_overrides_the_placeholder(self):
        used = mvm.addon_use("postgres", version="16", sha256="ab" * 32)
        assert used.sha256 == "ab" * 32

    @pytest.mark.parametrize(
        "kwargs",
        [
            {},  # neither
            {"version": "16", "path": "./x"},  # both
        ],
    )
    def test_exactly_one_of_version_or_path_is_required(self, kwargs):
        with pytest.raises(ValueError, match="exactly one of"):
            mvm.addon_use("postgres", **kwargs)


class TestWarmProcess:
    def test_defaults_match_the_cold_safe_shape(self):
        cfg = mvm.warm_process(max_calls_per_worker=1000, max_rss_mb=256)
        assert cfg.max_calls_per_worker == 1000
        assert cfg.max_rss_mb == 256
        assert cfg.pool_size == 1
        assert cfg.in_process.value == "serial"
        assert cfg.max_queue_depth is None

    def test_overrides_are_carried_through(self):
        cfg = mvm.warm_process(
            max_calls_per_worker=500,
            max_rss_mb=128,
            pool_size=4,
            in_process="concurrent",
            max_queue_depth=32,
        )
        assert cfg.pool_size == 4
        assert cfg.in_process.value == "concurrent"
        assert cfg.max_queue_depth == 32

    def test_an_unknown_dispatch_mode_is_refused(self):
        with pytest.raises(ValueError, match="must be 'serial' or 'concurrent'"):
            mvm.warm_process(
                max_calls_per_worker=1000, max_rss_mb=256, in_process="parallel"
            )


class TestGeneratedTierA:
    """Spot-checks that the generated constructors are the ones exported."""

    def test_host_port_validates_its_range(self):
        assert mvm.host_port("example.com", 443).port == 443
        with pytest.raises(ValueError, match="must be in 1..65535"):
            mvm.host_port("example.com", 0)

    def test_dns_resolver_defaults_to_the_dns_port(self):
        assert mvm.dns_resolver("1.1.1.1").port == 53

    def test_python_deps_accepts_the_hyphenated_alias(self):
        assert mvm.python_deps(lockfile="r.txt", tool="pip-tools").tool.value == "pip_tools"
