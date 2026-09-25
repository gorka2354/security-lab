"""tlsfix.py - make urllib verify TLS against a CURRENT CA bundle on hosts whose OS trust store is stale.

On the Windows workstation Python's OpenSSL trusts only the roots already present in the Windows store and never
triggers Windows' on-demand root update, so after a CA rotation api.etherscan.io (and Immunefi) fail with
"certificate has expired" while curl -- which ships its own bundle -- works. Every Etherscan-backed tool then
reported a FALSE NEGATIVE ("no verified source", "activity unknown") instead of an error (found 2026-09-25).

Imported for its side effect by every toolkit module that does HTTP (a golden test enforces that). Verification
stays ON -- only the trust roots change: certifi's Mozilla bundle, else Git-for-Windows' bundle. No-op off Windows
(the stand / CI stores are current) and when SSL_CERT_FILE is set (an explicit operator choice wins).
"""

import os
import ssl
import sys

_GIT_BUNDLES = (r"C:\Program Files\Git\mingw64\etc\ssl\certs\ca-bundle.crt",
                r"C:\Program Files\Git\usr\ssl\certs\ca-bundle.crt")


def bundle():
    """Path of a current CA bundle (certifi, else Git for Windows), or None."""
    try:
        import certifi
        return certifi.where()
    except Exception:
        return next((p for p in _GIT_BUNDLES if os.path.exists(p)), None)


def apply(platform=None, env=None):
    """Point urllib's default HTTPS context at bundle(). Returns the bundle in use, or None when left alone."""
    platform = platform or sys.platform
    env = os.environ if env is None else env
    if platform != "win32" or env.get("SSL_CERT_FILE"):
        return None
    b = bundle()
    if b:
        ssl._create_default_https_context = lambda: ssl.create_default_context(cafile=b)
    return b


BUNDLE = apply()
