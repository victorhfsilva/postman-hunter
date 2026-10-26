"""postman-hunter package.

Reuses the secret-hunter pattern catalog, LLM providers and classifier, and
adds Postman public-network collection search + scan.  The shared secret-hunter
package is resolved from SECRET_HUNTER_PATH (default /opt/secret-hunter).
"""

from __future__ import annotations

import os
import sys

__version__ = "1.0.0"

_SECRET_HUNTER_ROOT = os.environ.get("SECRET_HUNTER_PATH", "/opt/secret-hunter")
if os.path.isdir(_SECRET_HUNTER_ROOT) and _SECRET_HUNTER_ROOT not in sys.path:
    sys.path.insert(0, _SECRET_HUNTER_ROOT)

from .cli import main  # noqa: E402,F401

__all__ = ["main", "__version__"]
