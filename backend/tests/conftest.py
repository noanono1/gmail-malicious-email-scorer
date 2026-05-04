"""Pytest configuration shared by every test module.

`app.config` reads `HMAC_SECRET` from the environment at import time and binds
it to a module-level constant. Tests must seed a known value *before* the app
is imported anywhere in the suite. ``setdefault`` preserves a value the
developer has already configured locally (via shell or .env)."""

from __future__ import annotations

import os

os.environ.setdefault("HMAC_SECRET", "test-secret-for-pytest-only")
