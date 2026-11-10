"""report.py — the two iOwl reports, as printable pages.

    /api/report?kind=brief        the high-level brief, for leadership and staff
    /api/report?kind=technical    the technical report, for the security team

Both are built from findings.collect() and nothing else, so the two can never
disagree. Each is one HTML page, served over loopback like everything else, and
printed to PDF from the browser (the page carries a Print button).

What keeps a report safe to hand on:

  * Counts only. findings.py never reads a name, a number, an address or a
    message. The strings that DO come out of the stores (app bundle ids from the
    interaction log, the apps holding Full Disk Access) are passed through the
    redaction module before rendering. If redaction cannot run, those strings
    are withheld and the report says so: it fails closed.
  * Everything is escaped. Nothing a store holds is ever written as markup.
  * Every number links to the query that produced it, in the technical report's
    appendix; the brief names the store and gives the same reference id.

The page loads one stylesheet and one script, both from this server, so the
Content-Security-Policy the server sends stays as strict as it is for the app.
"""

import html
import time

from . import catalog, db, findings, redact

STORE_NAMES = {
    findings.GRAPH: "the knowledge graph",
    findings.SIRI: "the interaction log",
    findings.TAGGING: "the relationship scorecard",
    findings.CALENDAR: "Calendar",
}

SEVERITY_LABEL = {"high": "High", "medium": "Medium", "low": "Low", "info": "Note"}
WITHHELD = "(withheld: redaction could not run)"


# ------------------------------------------------------------------ helpers

def e(value):
    return html.escape("" if value is None else str(value), quote=True)


def num(value):
    if value is None:
        return '<span class="nm">not measured</span>'
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    return e(f"{value:,}" if isinstance(value, (int, float)) else value)


def when(unix, with_time=True):
    if not unix:
        return "unknown"
    fmt = "%B %d, %Y at %H:%M %Z" if with_time else "%B %d, %Y"
    return time.strftime(fmt, time.localtime(unix))


def ref_link(ref, kind):
    """A reference marker. In the technical report it links to the query; in
    the brief it names the id, which the technical report resolves."""
    if not ref:
        return ""
    first = str(ref).split("+")[0].split(",")[0]
    if kind == "technical":
        return f'<a class="ref" href="#{e(first)}">{e(ref)}</a>'
    return f'<span class="ref">{e(ref)}</span>'


def mv(m):
    return None if m is None else m.get("value")


def pill(severity):
    return f'<span class="sev sev-{e(severity)}">{e(SEVERITY_LABEL[severity])}</span>'


def _scrub_dynamic(data):
    """Redact the strings that came out of the stores. Returns a note when
    redaction could not run, in which case those strings are withheld."""
    try:
        comms = data.get("comms")
        if comms:
            for row in comms["apps"]:
                if row["kind"] is None:
                    row["bundle"] = redact.scrub(row["bundle"])
        prot = data.get("protections") or {}
        if prot.get("fda"):
            prot["fda"] = redact.scrub(prot["fda"])
        return None
    except Exception as exc:  # fail closed
        comms = data.get("comms")
        if comms:
            for row in comms["apps"]:
                if row["kind"] is None:
                    row["bundle"] = WITHHELD
        prot = data.get("protections") or {}
        if prot.get("fda"):
            prot["fda"] = [WITHHELD]
        return f"Redaction could not run ({type(exc).__name__}), so app names read from the stores are withheld."


def _head(title, kind, data):
    other = "technical" if kind == "brief" else "brief"
    other_label = "Technical report" if other == "technical" else "High-level brief"
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>{e(title)}</title>
<link rel="stylesheet" href="/css/report.css">
<link rel="icon" href="/logo.svg" type="image/svg+xml">
</head>
<body class="report report-{e(kind)}">
<div class="toolbar no-print">
  <button type="button" id="print">Print or save as PDF</button>
  <a href="/api/report?kind={e(other)}{e(_terms_qs(data))}">Open the {e(other_label.lower())}</a>
</div>
<main class="sheet">
<header class="masthead">
  <img src="/logo.svg" alt="" width="40" height="40">
  <div>
    <div class="mast-name">iOwl</div>
    <div class="mast-kind">{e(title)}</div>
  </div>
  <div class="mast-meta">
    <div>Generated {e(when(data['generated']))}</div>
    <div>{e(_scope_line(data))}</div>
  </div>
</header>
"""


def _terms_qs(data):
    terms = (data.get("watchlist") or {}).get("terms") or []
    if not terms:
        return ""
    from urllib.parse import quote
    return "&terms=" + quote(",".join(terms))


def _scope_line(data):
    if data["mode"] == "live":
        mac = f"macOS {data['macos']}" if data.get("macos") else "macOS version unknown"
        return f"This Mac, read live · {mac}"
    cap = data.get("captured")
    return "An extracted copy" + (f", last written {when(cap, False)}" if cap else "")


def _foot(data, kind):
    return f"""
<footer class="colophon">
  <p>{e(data['version'])}, built on iKnow by the Eighth Rank (Apache 2.0). Counts only: no name, number,
  address or message was read to produce this {'brief' if kind == 'brief' else 'report'}.
  iKnow is LLM-generated and iOwl extends it; check a finding against its source before relying on it.</p>
</footer>
</main>
<script src="/js/report.js"></script>
</body>
</html>
"""


# ------------------------------------------------------------------ the brief

def _tiles(data):
    prof, comms, score, apps = data.get("profile"), data.get("comms"), data.get("scorecard"), data.get("apps")
    tiles = []
    if prof:
        tiles.append((mv(prof["people"]), "people in the graph", prof["people"]["ref"]))
        tiles.append((mv(prof["people_outside_contacts"]), "were never in the contact list",
                      prof["people_outside_contacts"]["ref"]))
    if score and mv(score.get("scored")):
        tiles.append((mv(score["scored"]), "carry a relationship score", score["scored"]["ref"]))
    if comms:
        pm = comms["by_kind"]["private_messenger"]
        tiles.append((pm["entries"], "private-messenger entries in the log", comms["refs"]["apps"]))
        if comms.get("remote") and mv(comms["remote"]) is not None:
            tiles.append((mv(comms["remote"]), "log entries from other devices", comms["remote"]["ref"]))
    if apps:
        n = len({a["product"] for a in apps["security"]})
        tiles.append((n, "security tools named in the app list", apps["ref"]))
    return tiles[:6]


def brief(data):
    out = [_head("High-level brief", "brief", data)]
    found = data["findings"]
    serious = [f for f in found if f["severity"] in ("high", "medium")]
    notes = [f for f in found if f["severity"] in ("low", "info")]
    c = data["severity_counts"]

    out.append(f"""
<section class="lede">
  <h1>What this Mac knows, and what we do about it</h1>
  <p>macOS keeps a notebook on the person who uses it: who they know, who they talk to and how often,
  whose faces recur in their photos, and its own guesses about who is family. Apple documents very little
  of it and offers no way to look at it. This brief measures that notebook on one Mac.</p>
  <p class="quiet">Every figure is a count. No names, numbers or messages were read to produce it.
  {c['high']} high, {c['medium']} medium and {c['low']} low findings.</p>
</section>
""")

    tiles = _tiles(data)
    if tiles:
        out.append('<section class="tiles">')
        for value, label, ref in tiles:
            out.append(f'<div class="tile"><div class="tile-n">{num(value)}</div>'
                       f'<div class="tile-l">{e(label)} {ref_link(ref, "brief")}</div></div>')
        out.append("</section>")

    out.append('<section><h2>What we found</h2>')
    if not serious:
        out.append("<p>No high or medium findings were measured. See what this brief cannot tell you, below.</p>")
    for f in serious:
        out.append(f"""
<article class="finding">
  <h3>{pill(f['severity'])} {e(f['title'])}</h3>
  <p>{e(f['brief'])}</p>
  <p class="why"><b>Why it matters.</b> {e(f['impact'])}</p>
</article>""")
    if notes:
        out.append('<p class="also"><b>Also noted.</b> '
                   + " ".join(e(f["title"]) + "." for f in notes) + "</p>")
    out.append("</section>")

    actions = [a for a in data["actions"] if a["severity"] in ("high", "medium", "info")]
    if actions:
        out.append('<section><h2>What we do about it</h2><ol class="actions">')
        for a in actions:
            out.append(f"<li>{e(a['action'])}</li>")
        out.append("</ol></section>")

    out.append('<section><h2>What this brief cannot tell you</h2><ul class="open">')
    for u in data["unmeasured"]:
        out.append(f"<li><b>{e(u['area'])}:</b> not measured, because {e(u['reason'])}.</li>")
    for q in data["open_questions"]:
        out.append(f"<li>{e(q)}</li>")
    out.append("</ul></section>")

    out.append("""
<section class="close">
  <p>None of this is a breach. It is a record the Mac keeps to be helpful, and the lock on it is the login.</p>
</section>""")

    out.append('<section class="sources"><h2>Where the numbers come from</h2><p>Each reference '
               '(Q1, Q2 …) is a query in the technical report’s appendix, which gives the store and the exact SQL.</p>'
               "<ul>")
    used = set()
    for _v, label, ref in tiles:
        used.add(ref)
    for q in data["queries"]:
        if q["id"] in used:
            out.append(f'<li><span class="ref">{e(q["id"])}</span> {e(q["label"])}, from '
                       f'{e(STORE_NAMES.get(q["store"], q["store"]))}</li>')
    out.append("</ul></section>")
    out.append(_foot(data, "brief"))
    return "".join(out)


# ------------------------------------------------------------------ the technical report

def technical(data, note):
    K = "technical"
    out = [_head("Technical report", K, data)]
    found = data["findings"]

    # 1. scope
    out.append('<section><h1>Exposure of the macOS personal knowledge graph</h1>'
               '<h2>1. Scope and method</h2><table class="kv">')
    rows = [
        ("Generated", when(data["generated"])),
        ("Mode", data["mode"]),
        ("macOS", data.get("macos") or "not known (an extracted copy, or not read live)"),
        ("Graph last written", when(data.get("captured"))),
        ("Tool", data["version"] + ", built on iKnow (github.com/8rank/iKnow)"),
    ]
    for k, v in rows:
        out.append(f"<tr><th>{e(k)}</th><td>{e(v)}</td></tr>")
    out.append("</table>")
    out.append("""<p>Every store was opened read-only (<span class="mono">mode=ro</span>). Every measure is
    an aggregate query; no query returns a name, phone number, address or message. App identifiers read from
    the stores pass through iOwl's redaction before they are shown. Message text is never searched.
    A measure that could not be taken is reported as <i>not measured</i>, never as zero.</p>""")
    if note:
        out.append(f'<p class="warn">{e(note)}</p>')
    red_gaps = [g for g in db.gaps() if g.get("kind") == "redact"]
    if red_gaps:
        out.append('<p class="warn">Redaction ran with gaps: '
                   + "; ".join(e(g["detail"]) for g in red_gaps) + ".</p>")

    out.append('<h3>Stores</h3><table class="grid fixed stores"><tr><th class="w-store">Store and SHA-256 '
               '(main file)</th><th>What it is</th><th class="w-state">State</th><th class="r w-bytes">Bytes</th></tr>')
    for s in data["stores"]:
        out.append(f'<tr><td><div class="mono wrap">{e(s["store"])}</div>'
                   f'<div class="mono small quiet wrap">{e(s["sha256"] or "no hash")}</div></td>'
                   f'<td>{e(s["label"])}</td><td>{e(s["state"])}</td>'
                   f'<td class="r">{num(s["bytes"]) if s["bytes"] is not None else "–"}</td></tr>')
    out.append('</table><p class="small quiet">Hashes cover the main database file only. A live store also '
               'has a write-ahead log that changes while the daemons run, so two runs a minute apart can differ.</p>')
    out.append("</section>")

    # 2. summary
    out.append('<section><h2>2. Summary of findings</h2><table class="grid"><tr><th>ID</th>'
               '<th>Severity</th><th>Finding</th></tr>')
    for f in found:
        out.append(f'<tr><td><a href="#{e(f["id"])}">{e(f["id"])}</a></td><td>{pill(f["severity"])}</td>'
                   f'<td>{e(f["title"])}</td></tr>')
    out.append("</table>")
    out.append('<p class="small quiet">Severity reflects how directly the finding exposes people to harm if '
               'the device is examined or compromised. It is a judgment, stated so it can be argued with.</p></section>')

    # 3. findings
    out.append("<section><h2>3. Findings</h2>")
    for f in found:
        out.append(f'<article class="finding" id="{e(f["id"])}"><h3>{e(f["id"])} {pill(f["severity"])} '
                   f'{e(f["title"])}</h3><p>{e(f["brief"])}</p>'
                   f'<p class="small"><b>How it was measured.</b> {e(f["detail"])}</p>')
        if f["evidence"]:
            out.append('<table class="grid ev"><tr><th>Measure</th><th class="r">Value</th><th>Query</th></tr>')
            for ev in f["evidence"]:
                out.append(f'<tr><td>{e(ev["label"])}</td><td class="r">{num(ev["value"])}</td>'
                           f'<td>{ref_link(ev.get("ref"), K)}</td></tr>')
            out.append("</table>")
        out.append(f'<p><b>Impact.</b> {e(f["impact"])}</p>')
        if f["actions"]:
            out.append("<p><b>Actions.</b></p><ul>" + "".join(f"<li>{e(a)}</li>" for a in f["actions"]) + "</ul>")
        out.append("</article>")
    out.append("</section>")

    # 4. profile
    prof = data.get("profile")
    out.append("<section><h2>4. Profile of the graph</h2>")
    if prof:
        labels = [
            ("facts", "Facts in the live graph"), ("people", "People"),
            ("people_contacts", "People from Contacts"),
            ("people_outside_contacts", "People never in Contacts"),
            ("people_photos", "People from Photos face clusters"),
            ("people_unnamed", "People with no name"), ("people_faces", "People bound to a face cluster"),
            ("people_reachable", "People with a phone number or mail address"),
            ("people_employer", "People with an employer"), ("people_address", "People with a postal address"),
            ("people_family_sharing", "People from Family Sharing"), ("orgs", "Organizations"),
            ("places", "Places"), ("events", "Calendar events and reservations"),
            ("events_described", "Events with a full description"),
            ("event_attendees", "Distinct event attendees"), ("expired", "Withdrawn facts still held"),
            ("embeddings", "Rows in the embeddings table"),
        ]
        out.append('<table class="grid"><tr><th>Measure</th><th class="r">Value</th><th>Query</th></tr>')
        for key, label in labels:
            m = prof.get(key)
            if m is None:
                continue
            out.append(f'<tr><td>{e(label)}</td><td class="r">{num(mv(m))}</td><td>{ref_link(m["ref"], K)}</td></tr>')
        if prof.get("archive_hours") is not None:
            out.append(f'<tr><td>Withdrawal archive window, hours</td><td class="r">{num(prof["archive_hours"])}</td>'
                       f'<td>{ref_link((prof.get("prune") or {}).get("ref"), K)}</td></tr>')
        out.append("</table>")
    else:
        out.append("<p>Not measured: the graph could not be read.</p>")
    score = data.get("scorecard")
    if score:
        out.append('<h3>Relationship scorecard</h3><table class="grid"><tr><th>Measure</th>'
                   '<th class="r">Value</th><th>Query</th></tr>')
        for key, label in (("scored", "Entities scored"), ("with_role", "Given a specific family role"),
                           ("orgs_scored", "Organizations among the scored")):
            if score.get(key):
                out.append(f'<tr><td>{e(label)}</td><td class="r">{num(mv(score[key]))}</td>'
                           f'<td>{ref_link(score[key]["ref"], K)}</td></tr>')
        out.append("</table>")
        if score.get("role_columns"):
            out.append(f'<p class="small quiet">Role columns present in this copy: '
                       f'{e(", ".join(score["role_columns"]))}.</p>')
    out.append("</section>")

    # 5. communication log
    comms = data.get("comms")
    out.append("<section><h2>5. Communication log by app</h2>")
    if comms:
        first, last = mv(comms["first"]), mv(comms["last"])
        out.append(f'<p>{num(mv(comms["total"]))} entries {ref_link(comms["total"]["ref"], K)}, from '
                   f'{e(when(db.apple_time(first), False))} to {e(when(db.apple_time(last), False))}. '
                   'Contacts are distinct handles (a phone number or an app account id); groups are distinct '
                   'chats. Values are counted, never shown.</p>')
        remote_hdr = '<th class="r">From other devices</th>' if comms["remote_column"] else ""
        out.append('<table class="grid"><tr><th>App</th><th>Kind</th><th class="r">Entries</th>'
                   f'<th class="r">Contacts</th><th class="r">Groups</th>{remote_hdr}<th>From</th><th>To</th></tr>')
        for r in comms["apps"]:
            name = r["product"] or r["bundle"]
            sub = f'<div class="mono small">{e(r["bundle"])}</div>' if r["product"] else ""
            rem = f'<td class="r">{num(r["remote"])}</td>' if comms["remote_column"] else ""
            out.append(f'<tr><td>{e(name)}{sub}</td><td>{e(r["kind_label"] or "unclassified")}</td>'
                       f'<td class="r">{num(r["entries"])}</td><td class="r">{num(r["handles"])}</td>'
                       f'<td class="r">{num(r["groups"])}</td>{rem}<td>{e(r["first"])}</td><td>{e(r["last"])}</td></tr>')
        out.append(f'</table><p class="small quiet">Queries: entries {ref_link(comms["refs"]["apps"], K)}, '
                   f'contacts {ref_link(comms["refs"]["handles"], K)}, groups {ref_link(comms["refs"]["groups"], K)}.'
                   + (" Rows from other devices are identified by the "
                      f'<span class="mono">{e(comms["remote_column"])}</span> column.' if comms["remote_column"] else
                      " This copy of the log has no device column.") + "</p>")
    else:
        out.append("<p>Not measured: the interaction log could not be read.</p>")
    out.append("</section>")

    # 6. software
    apps = data.get("apps")
    out.append("<section><h2>6. Security and management software in the app list</h2>")
    if apps:
        out.append(f'<p>{num(mv(apps["count"]))} apps in the {e(apps["source"])} inventory '
                   f'{ref_link(apps["ref"], K)}. Matched against the rules in Appendix B.</p>')
        if apps["security"]:
            out.append('<table class="grid"><tr><th>Product</th><th>Kind</th><th>Bundle id</th></tr>')
            for a in apps["security"]:
                out.append(f'<tr><td>{e(a["product"])}</td><td>{e(a["kind_label"])}</td>'
                           f'<td class="mono small">{e(a["bundle"])}</td></tr>')
            out.append("</table>")
        else:
            out.append("<p>No app matched a security rule.</p>")
    else:
        out.append("<p>Not measured: no app inventory could be read.</p>")
    out.append("</section>")

    # 7. protections
    prot = data.get("protections") or {}
    out.append("<section><h2>7. Protections on this Mac</h2>")
    if prot.get("measured"):
        out.append(f'<table class="kv"><tr><th>FileVault</th><td>{e(prot.get("filevault") or "not measured")} '
                   f'{ref_link(prot.get("filevault_ref"), K)}</td></tr>')
        fda = prot.get("fda")
        out.append(f'<tr><th>Full Disk Access</th><td>'
                   + (f'{len(fda)} apps {ref_link(prot.get("fda_ref"), K)}' if fda is not None else "not measured")
                   + "</td></tr></table>")
        if fda:
            out.append('<ul class="mono small cols">' + "".join(f"<li>{e(x)}</li>" for x in fda) + "</ul>")
    else:
        out.append(f'<p>Not measured: {e(prot.get("reason"))}.</p>')
    out.append("</section>")

    # 8. watchlist
    watch = data["watchlist"]
    out.append("<section><h2>8. Organization watchlist</h2>")
    if watch["terms"]:
        cols = [("graph", "Graph"), ("withdrawn", "Withdrawn"), ("log", "Interaction log"),
                ("calendar", "Calendar"), ("contacts", "Contacts")]
        out.append('<table class="grid"><tr><th>Term</th>' + "".join(f'<th class="r">{e(l)}</th>' for _k, l in cols)
                   + '<th class="r">Total</th></tr>')
        for r in watch["rows"]:
            cells = "".join(
                f'<td class="r">{num(r[k]) if k in r else "–"} {ref_link(r.get(k + "_ref"), K) if k in r else ""}</td>'
                for k, _l in cols)
            out.append(f'<tr><td>{e(r["term"])}</td>{cells}<td class="r"><b>{num(r["total"])}</b></td></tr>')
        out.append(f'</table><p class="small quiet">Case-insensitive substring counts. Searched: '
                   f'{e(", ".join(watch["searched"]) or "nothing readable")}. A dash means that store could not be '
                   f'read. {e(watch["not_searched"])}</p>')
    else:
        out.append("<p>No terms were given. Add them to <span class=\"mono\">watchlist.txt</span> beside "
                   "server.py, or on the Reports page.</p>")
    out.append("</section>")

    # 9. limits
    out.append('<section><h2>9. Not measured, and open questions</h2><ul class="open">')
    for u in data["unmeasured"]:
        out.append(f"<li><b>{e(u['area'])}:</b> not measured, because {e(u['reason'])}.</li>")
    for q in data["open_questions"]:
        out.append(f"<li>{e(q)}</li>")
    out.append("</ul></section>")

    # appendices
    out.append('<section class="appendix"><h2>Appendix A. Queries</h2><p class="small quiet">Every number in '
               'this report, with the store and the exact statement that produced it.</p>'
               '<table class="grid fixed q"><tr><th class="w-ref">Ref</th><th class="w-measure">Measure and store</th>'
               '<th>Statement</th></tr>')
    for q in data["queries"]:
        params = f'<div class="small quiet">parameters: {e(", ".join(q["params"]))}</div>' if q["params"] else ""
        out.append(f'<tr id="{e(q["id"])}"><td>{e(q["id"])}</td><td>{e(q["label"])}'
                   f'<div class="mono small quiet wrap">{e(q["store"])}</div></td>'
                   f'<td><code>{e(q["sql"])}</code>{params}</td></tr>')
    out.append("</table></section>")

    out.append('<section class="appendix"><h2>Appendix B. App classification rules</h2><p class="small quiet">'
               'A bundle id is matched case-insensitively against the start of each prefix. A bundle that '
               'matches nothing is reported as unclassified. Edit <span class="mono">api/catalog.py</span> to '
               'change the rules.</p><table class="grid"><tr><th>Kind</th><th>Prefix</th><th>Product</th></tr>')
    for r in data["rules"]:
        out.append(f'<tr><td>{e(r["label"])}</td><td class="mono small">{e(r["prefix"])}</td>'
                   f'<td>{e(r["product"])}</td></tr>')
    out.append("</table></section>")

    out.append(_foot(data, "technical"))
    return "".join(out)


# ------------------------------------------------------------------ handler

def handler(params):
    kind = (params.get("kind") or "brief").lower()
    if kind not in ("brief", "technical"):
        kind = "brief"
    data = findings.collect(params)
    note = _scrub_dynamic(data)
    page = brief(data) if kind == "brief" else technical(data, note)
    return (200, "text/html; charset=utf-8", page.encode("utf-8"))


ROUTES = {"/api/report": handler}
