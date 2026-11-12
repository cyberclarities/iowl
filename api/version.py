"""version.py — iOwl's version number, in one place.

The sidebar shows it beside the name (it asks /api/version), and both reports
print it in their footer and scope table (findings.VERSION), so the app and
anything printed from it always agree.
"""

VERSION = "0.3"


def handler(params):
    return {"version": VERSION}


ROUTES = {"/api/version": handler}
