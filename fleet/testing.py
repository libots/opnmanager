"""Test runner that gives each test run its own temporary data directory.

Without it, tests write lock files (and anything else keyed on DATA_DIR) into the
configured data directory, by default the checkout, where they could collide with a
local installation's live device-write locks.
"""

import tempfile
from pathlib import Path

from django.test.runner import DiscoverRunner
from django.test.utils import override_settings


class DataDirTestRunner(DiscoverRunner):
    def setup_test_environment(self, **kwargs):
        super().setup_test_environment(**kwargs)
        self._data_dir = tempfile.TemporaryDirectory(prefix="opnmanager-test-")
        self._data_dir_override = override_settings(DATA_DIR=Path(self._data_dir.name))
        self._data_dir_override.enable()

    def teardown_test_environment(self, **kwargs):
        self._data_dir_override.disable()
        self._data_dir.cleanup()
        super().teardown_test_environment(**kwargs)


def make_rule(*interfaces, **fields):
    """Create a manager rule bound to the given logical interfaces (tests only)."""
    from .models import Rule

    rule = Rule.objects.create(**fields)
    rule.interfaces.set(interfaces)
    return rule
