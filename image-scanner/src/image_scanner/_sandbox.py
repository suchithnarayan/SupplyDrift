"""Shared sandbox executor for all image-scanner cataloguer invocations."""
from __future__ import annotations

import logging

from supplydrift_sandbox import SandboxExecutor

tool_sandbox = SandboxExecutor(logger=logging.getLogger("image_scanner.sandbox"))
