"""findings.py — measurements turned into findings, for both iOwl reports.

The viewer pages answer "what is in the store". This module answers the
question a reader of a security report asks next: "so what, and what do we do".
It measures a fixed set of things, applies a fixed set of rules, and returns
findings, each with its evidence, its impact and its actions.

Four rules hold throughout:

1. COUNTS ONLY. No query here returns a person's name, number, address or
   message. What leaves this module is counts, dates, app bundle ids (vendor
   product ids, not personal data) and the watchlist terms the reader typed.
   The report module scrubs the payload again before rendering, and fails
   closed if it cannot.
2. EVERY NUMBER HAS A SOURCE. Each value goes through Ledger, which records the
   store and the exact SQL that produced it under a reference id (Q1, Q2 …).
   The technical report prints every one.
3. NOT MEASURED IS NOT ZERO. A store that is absent or unreadable gives None,
   and a finding that depends on it moves to the "not measured" list with the
   reason. An empty table gives 0, and a zero can be a finding in its own
   right ("no entries from other devices").
4. CLAIMS STAY INSIDE THE EVIDENCE. Where a recommendation has not been shown
   to work, it says so. Where a question is open (does any of this leave the
   Mac?), the report lists it as open.

Everything is computed at request time. Nothing is written anywhere.
"""

import hashlib
import os
import platform
import sqlite3
import subprocess
import sys
import time

from . import biome, catalog, db

VERSION = "iOwl 0.1"

GRAPH = "graph/graph.db"
SIRI = "graph/Artifacts__siri__remembers__view.db"
TAGGING = "graph/Artifacts__entityTagging__entityTagging.db"
CALENDAR = "sources/Calendar.sqlitedb"
TCC_DB = "/Library/Application Support/com.apple.TCC/TCC.db"
WATCHLIST_FILE = os.path.join(db.ROOT, "watchlist.txt")

PEOPLE = ("(SELECT subject FROM stable_graph WHERE predicate = 'PS1' "
          "AND relationshipId = 0 AND object = 'SB104')")
CONTACTS_BIT = 1 << 0
PHOTOS_BIT = 1 << 5
FAMILY_BIT = 1 << 13

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

MAX_TERMS = 25
MAX_TERM_LEN = 64
MAX_HASH_BYTES = 512 * 1024 * 1024


# ------------------------------------------------------------------ ledger

class Ledger:
    """Every measurement and the query behind it."""

    def __init__(self):
        self.refs = []
        self._seen = {}

    def ref(self, label, store, sql, params=()):
        key = (store, " ".join(sql.split()), tuple(str(p) for p in params))
        if key not in self._seen:
            rid = f"Q{len(self.refs) + 1}"
            self.refs.append({"id": rid, "label": label, "store": store,
                              "sql": key[1], "params": list(key[2])})
            self._seen[key] = rid
        return self._seen[key]

    def one(self, label, store, sql, params=()):
        """A single number, or None when the store could not answer."""
        value = db.one(store, sql, params, default=None)
        return {"value": value, "ref": self.ref(label, store, sql, params)}

    def rows(self, label, store, sql, params=()):
        return db.query(store, sql, params), self.ref(label, store, sql, params)

    def system(self, label, command):
        return self.ref(label, "system", command)


def _v(m):
    """The value of a measurement, or None."""
    return None if m is None else m.get("value")


def _ev(label, m, note=None):
    """One evidence line for a finding."""
    out = {"label": label, "value": _v(m), "ref": (m or {}).get("ref")}
    if note:
        out["note"] = note
    return out


def _n(x):
    return f"{x:,}" if isinstance(x, (int, float)) else "not measured"


def _count(n, one, many=None):
    """'1 group', '4 groups', 'not measured'."""
    if not isinstance(n, (int, float)):
        return "not measured"
    return f"{n:,} {one if n == 1 else (many or one + 's')}"


def _pct(part, whole):
    if not whole or part is None:
        return None
    return round(100.0 * part / whole, 1)


def _month(apple_ts):
    unix = db.apple_time(apple_ts)
    return time.strftime("%Y-%m", time.gmtime(unix)) if unix else None


# ------------------------------------------------------------------ the stores

STORES = [
    (GRAPH, "The knowledge graph"),
    (SIRI, "The interaction log (messages and calls, metadata only)"),
    (TAGGING, "The relationship scorecard"),
    (CALENDAR, "Calendar"),
]


def _readable(rel):
    with db.probe():
        try:
            return db.connect(rel) is not None
        except Exception:
            return False


def _stores():
    """What could be read, with a hash of the main file for the record. Paths
    are given relative to the store root: a full path carries the account
    name."""
    out = []
    names = list(STORES) + [(rel, "Contacts (" + name.split(".")[0][:8] + "…)")
                            for name, rel in db.address_books()]
    for rel, label in names:
        path = db.resolve(rel)
        ok = _readable(rel)
        state = "read" if ok else (db.why_not(path) or ("absent", ""))[0]
        entry = {"store": rel, "label": label, "state": state,
                 "bytes": None, "sha256": None}
        if ok:
            try:
                size = os.path.getsize(path)
                entry["bytes"] = size
                if size <= MAX_HASH_BYTES:
                    h = hashlib.sha256()
                    with open(path, "rb") as fh:
                        for chunk in iter(lambda: fh.read(1 << 20), b""):
                            h.update(chunk)
                    entry["sha256"] = h.hexdigest()
            except OSError:
                pass
        out.append(entry)
    return out


# ------------------------------------------------------------------ measurements

def _profile(L):
    if not _readable(GRAPH):
        return None

    def q(label, sql):
        return L.one(label, GRAPH, sql)

    p = {
        "facts": q("Facts in the live graph",
                   "SELECT (SELECT COUNT(*) FROM stable_graph) + (SELECT COUNT(*) FROM event_graph)"),
        "people": q("People in the graph", f"SELECT COUNT(*) FROM {PEOPLE}"),
        "people_contacts": q("People asserted by Contacts",
            f"SELECT COUNT(DISTINCT subject) FROM stable_graph WHERE subject IN {PEOPLE} "
            f"AND (sources & {CONTACTS_BIT}) <> 0"),
        "people_outside_contacts": q("People with no fact from Contacts",
            f"SELECT COUNT(*) FROM {PEOPLE} p WHERE NOT EXISTS (SELECT 1 FROM stable_graph s "
            f"WHERE s.subject = p.subject AND (s.sources & {CONTACTS_BIT}) <> 0)"),
        "people_photos": q("People asserted by Photos face clusters",
            f"SELECT COUNT(DISTINCT subject) FROM stable_graph WHERE subject IN {PEOPLE} "
            f"AND (sources & {PHOTOS_BIT}) <> 0"),
        "people_unnamed": q("People with no name in the graph",
            f"SELECT COUNT(*) FROM {PEOPLE} p WHERE NOT EXISTS (SELECT 1 FROM stable_graph s "
            f"WHERE s.subject = p.subject AND s.predicate IN ('PS33','PS312','PS441'))"),
        "people_faces": q("People bound to a face cluster",
            f"SELECT COUNT(DISTINCT subject) FROM stable_graph WHERE subject IN {PEOPLE} "
            f"AND predicate = 'nm_hasVisualIdentifier'"),
        "people_reachable": q("People with a phone number or mail address",
            f"SELECT COUNT(DISTINCT subject) FROM stable_graph WHERE subject IN {PEOPLE} "
            f"AND predicate = 'PS520'"),
        "people_employer": q("People with an employer",
            f"SELECT COUNT(DISTINCT subject) FROM stable_graph WHERE subject IN {PEOPLE} "
            f"AND predicate = 'PS500'"),
        "people_address": q("People with a postal address",
            f"SELECT COUNT(DISTINCT subject) FROM stable_graph WHERE subject IN {PEOPLE} "
            f"AND predicate = 'PS317'"),
        "people_family_sharing": q("People asserted by Family Sharing",
            f"SELECT COUNT(DISTINCT subject) FROM stable_graph WHERE subject IN {PEOPLE} "
            f"AND (sources & {FAMILY_BIT}) <> 0"),
        "orgs": q("Organizations",
            "SELECT COUNT(DISTINCT subject) FROM stable_graph WHERE predicate = 'PS1' "
            "AND relationshipId = 0 AND object = 'SB10'"),
        "places": q("Places",
            "SELECT COUNT(DISTINCT subject) FROM stable_graph WHERE predicate = 'PS1' "
            "AND relationshipId = 0 AND object = 'SB152'"),
        "events": q("Calendar events and reservations",
            "SELECT COUNT(DISTINCT subject) FROM event_graph"),
        "events_described": q("Events carrying a full description",
            "SELECT COUNT(DISTINCT subject) FROM event_graph WHERE predicate = 'PS51'"),
        "event_attendees": q("Distinct people attending events",
            "SELECT COUNT(DISTINCT object) FROM event_graph WHERE predicate = 'PS232' "
            "AND relationshipPredicate = 'PS143'"),
        "owner": q("Entities marked as the owner",
            "SELECT COUNT(*) FROM stable_graph WHERE predicate = 'nm_isCurrentUser'"),
        "captured": q("Newest write in the graph (Apple time)",
            "SELECT MAX(timestamp) FROM stable_graph"),
    }

    if db.has_table(GRAPH, "expired_stable_graph"):
        p["expired"] = q("Withdrawn facts still held",
            "SELECT (SELECT COUNT(*) FROM expired_stable_graph) + "
            "(SELECT COUNT(*) FROM expired_event_graph)")
    if db.has_table(GRAPH, "graph_state"):
        p["prune"] = q("Withdrawal archive cut-off (Apple time)",
            "SELECT value FROM graph_state WHERE key = 'expiredTriplesPruneTimestamp'")
    if db.has_table(GRAPH, "embeddings"):
        p["embeddings"] = q("Rows in the embeddings table", "SELECT COUNT(*) FROM embeddings")
        p["embedding_types"] = q("Embedding types",
            "SELECT COUNT(DISTINCT embeddingType) FROM embeddings")

    cap, prune = _v(p.get("captured")), _v(p.get("prune"))
    p["archive_hours"] = (round((float(cap) - float(prune)) / 3600.0, 1)
                          if cap and prune and float(cap) > float(prune) else None)
    p["captured_unix"] = db.apple_time(cap) if cap else None
    return p


def _scorecard(L):
    if not _readable(TAGGING) or not db.has_table(TAGGING, "entity_tagging"):
        return None
    cols = [c["name"] for c in db.query(TAGGING, "PRAGMA table_info(entity_tagging)")]
    roles = [c for c in ("partner", "spouse", "mother", "father", "parent",
                         "sibling", "child", "daughter", "son") if c in cols]
    out = {"scored": L.one("Entities carrying relationship scores", TAGGING,
                           "SELECT COUNT(*) FROM entity_tagging"),
           "role_columns": roles}
    if roles:
        cond = " OR ".join(f'COALESCE("{c}", 0) > 0' for c in roles)
        out["with_role"] = L.one("Entities given a specific family role", TAGGING,
                                 f"SELECT COUNT(*) FROM entity_tagging WHERE {cond}")
    # Which scored entities are organizations: ids from one store, classes from
    # the other, met in memory. Ids only; no name is read.
    if _readable(GRAPH):
        ids, r1 = L.rows("Scored entity ids", TAGGING, "SELECT mdid FROM entity_tagging")
        orgs, r2 = L.rows("Organization ids", GRAPH,
            "SELECT DISTINCT subject FROM stable_graph WHERE predicate = 'PS1' "
            "AND relationshipId = 0 AND object = 'SB10'")
        org_ids = {str(r["subject"]) for r in orgs}
        n = sum(1 for r in ids if str(r["mdid"]).strip() in org_ids)
        out["orgs_scored"] = {"value": n, "ref": r1 + "+" + r2}
    return out


def _comms(L):
    if not _readable(SIRI) or not db.has_table(SIRI, "interactions"):
        return None
    cols = {c["name"] for c in db.query(SIRI, "PRAGMA table_info(interactions)")}

    out = {
        "total": L.one("Entries in the interaction log", SIRI, "SELECT COUNT(*) FROM interactions"),
        "first": L.one("Oldest entry (Apple time)", SIRI, "SELECT MIN(startDate) FROM interactions"),
        "last": L.one("Newest entry (Apple time)", SIRI, "SELECT MAX(startDate) FROM interactions"),
    }

    apps, r_apps = L.rows("Entries per app", SIRI, """
        SELECT bundleId AS bundle, COUNT(*) AS entries,
               MIN(startDate) AS first, MAX(startDate) AS last
        FROM interactions GROUP BY 1 ORDER BY entries DESC""")
    handles, r_h = L.rows("Distinct handles per app", SIRI, """
        SELECT i.bundleId AS bundle, COUNT(DISTINCT e.id) AS n
        FROM interactions i
        JOIN interactionEntities ie ON ie.interactionRowid = i.rowid
        JOIN entities e ON e.rowid = ie.entityRowid
        WHERE e.type = 'PersonHandle' GROUP BY 1""")
    groups, r_g = L.rows("Distinct chats and groups per app", SIRI, """
        SELECT i.bundleId AS bundle, COUNT(DISTINCT e.rowid) AS n
        FROM interactions i
        JOIN interactionEntities ie ON ie.interactionRowid = i.rowid
        JOIN entities e ON e.rowid = ie.entityRowid
        WHERE e.type = 'MessageGroup' GROUP BY 1""")

    remote_col = None
    if "remoteDeviceId" in cols:
        remote_col = "remoteDeviceId"
        remote_where = "remoteDeviceId IS NOT NULL AND remoteDeviceId <> ''"
    elif "isLocal" in cols:
        remote_col = "isLocal"
        remote_where = "isLocal = 0"
    remote_by_app = {}
    if remote_col:
        out["remote"] = L.one("Entries recorded on another device", SIRI,
                              f"SELECT COUNT(*) FROM interactions WHERE {remote_where}")
        if remote_col == "remoteDeviceId":
            out["remote_devices"] = L.one("Other devices feeding the log", SIRI,
                f"SELECT COUNT(DISTINCT remoteDeviceId) FROM interactions WHERE {remote_where}")
        rows, r_r = L.rows("Entries from other devices, per app", SIRI,
            f"SELECT bundleId AS bundle, COUNT(*) AS n FROM interactions "
            f"WHERE {remote_where} GROUP BY 1")
        remote_by_app = {r["bundle"]: r["n"] for r in rows}
    out["remote_column"] = remote_col

    hmap = {r["bundle"]: r["n"] for r in handles}
    gmap = {r["bundle"]: r["n"] for r in groups}
    table = []
    for a in apps:
        kind, label, product = catalog.classify(a["bundle"])
        table.append({
            "bundle": a["bundle"] or "(none)",
            "product": product, "kind": kind, "kind_label": label,
            "entries": a["entries"],
            "handles": hmap.get(a["bundle"], 0),
            "groups": gmap.get(a["bundle"], 0),
            "remote": remote_by_app.get(a["bundle"], 0) if remote_col else None,
            "first": _month(a["first"]), "last": _month(a["last"]),
        })
    out["apps"] = table
    out["refs"] = {"apps": r_apps, "handles": r_h, "groups": r_g}

    def kind_sum(kind, key):
        return sum(r[key] or 0 for r in table if r["kind"] == kind)

    def kind_distinct(kind, entity_type, label):
        """Distinct across the kind's apps, not a sum: one person reached on
        both Signal and WhatsApp is one contact."""
        bundles = [a["bundle"] for a in apps if catalog.classify(a["bundle"])[0] == kind]
        if not bundles:
            return 0, None
        marks = ",".join("?" * len(bundles))
        col = "e.id" if entity_type == "PersonHandle" else "e.rowid"
        m = L.one(label, SIRI,
                  f"SELECT COUNT(DISTINCT {col}) FROM interactions i "
                  f"JOIN interactionEntities ie ON ie.interactionRowid = i.rowid "
                  f"JOIN entities e ON e.rowid = ie.entityRowid "
                  f"WHERE e.type = '{entity_type}' AND i.bundleId IN ({marks})", tuple(bundles))
        return m["value"] or 0, m["ref"]

    out["by_kind"] = {}
    for k in catalog.COMMS_KINDS:
        handles, h_ref = kind_distinct(k, "PersonHandle", f"Distinct contacts across {k} apps")
        groups_n, g_ref = kind_distinct(k, "MessageGroup", f"Distinct groups across {k} apps")
        out["by_kind"][k] = {
            "entries": kind_sum(k, "entries"), "handles": handles, "groups": groups_n,
            "handles_ref": h_ref, "groups_ref": g_ref,
            "products": sorted({r["product"] for r in table if r["kind"] == k}),
        }
    return out


def _apps(L):
    source = "graph"
    bundles = []
    if _readable(GRAPH):
        rows, ref = L.rows("Installed apps recorded in the graph", GRAPH,
                           "SELECT DISTINCT object AS bundle FROM stable_graph "
                           "WHERE predicate = 'nm_bundleID'")
        bundles = [r["bundle"] for r in rows if r["bundle"]]
    else:
        ref = None
    if not bundles:
        with db.probe():
            try:
                apps, _skipped = biome.installed_apps()
            except Exception:
                apps = []
        if apps:
            source = "biome"
            bundles = [a["bundle"] for a in apps]
            ref = L.ref("Installed apps from the Biome set", biome.INSTALLED_APPS,
                        "metacontent_provenance JOIN metacontent JOIN content "
                        "(deleted_run_length = 0), field 1")
    if not bundles:
        return None

    security = []
    for b in sorted(set(bundles)):
        kind, label, product = catalog.classify(b)
        if kind in catalog.SECURITY_KINDS:
            security.append({"bundle": b, "kind": kind, "kind_label": label, "product": product})
    return {"count": {"value": len(set(bundles)), "ref": ref},
            "source": source, "security": security, "ref": ref}


def _protections(L):
    """FileVault and Full Disk Access. Only on this Mac, live: an extracted copy
    says nothing about the machine it came from."""
    if not db.live() or sys.platform != "darwin":
        return {"measured": False,
                "reason": "iOwl checks these only when it runs live on the Mac itself"}
    out = {"measured": True}

    try:
        res = subprocess.run(["/usr/bin/fdesetup", "status"], capture_output=True,
                             text=True, timeout=10)
        text = (res.stdout or "") + (res.stderr or "")
        out["filevault"] = ("on" if "FileVault is On" in text
                            else "off" if "FileVault is Off" in text else None)
    except (OSError, subprocess.SubprocessError):
        out["filevault"] = None
    out["filevault_ref"] = L.system("FileVault status", "/usr/bin/fdesetup status")

    sql = ("SELECT client, client_type FROM access "
           "WHERE service = 'kTCCServiceSystemPolicyAllFiles' AND auth_value = 2")
    out["fda_ref"] = L.ref("Apps granted Full Disk Access", "system:TCC.db", sql)
    try:
        conn = sqlite3.connect(f"file:{TCC_DB}?mode=ro", uri=True)
        conn.text_factory = lambda b: b.decode("utf-8", "replace")
        try:
            rows = conn.execute(sql).fetchall()
        finally:
            conn.close()
        # A path names its folder and can carry the account name: keep the
        # last component only.
        out["fda"] = sorted({(c if t == 0 else os.path.basename(c.rstrip("/"))) for c, t in rows})
    except sqlite3.Error:
        out["fda"] = None
    out["macos"] = platform.mac_ver()[0] or None
    return out


# ------------------------------------------------------------------ watchlist

def watch_terms(params):
    """Terms from watchlist.txt beside server.py, plus any the page sent."""
    terms = []
    try:
        with open(WATCHLIST_FILE, encoding="utf-8") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if line:
                    terms.append(line)
    except OSError:
        pass
    raw = (params or {}).get("terms") or ""
    for part in raw.replace("\n", ",").split(","):
        if part.strip():
            terms.append(part.strip())
    seen, out = set(), []
    for t in terms:
        t = t[:MAX_TERM_LEN]
        key = t.lower()
        if len(key) >= 2 and key not in seen:
            seen.add(key)
            out.append(t)
    return out[:MAX_TERMS]


def _watchlist(L, terms):
    if not terms:
        return {"terms": [], "rows": [], "searched": []}
    graph_ok = _readable(GRAPH)
    siri_ok = _readable(SIRI) and db.has_table(SIRI, "entities")
    cal_ok = _readable(CALENDAR) and db.has_table(CALENDAR, "CalendarItem")
    books = [rel for _name, rel in db.address_books() if _readable(rel)]
    has_expired = graph_ok and db.has_table(GRAPH, "expired_stable_graph")

    rows = []
    for term in terms:
        t = term.lower()
        row = {"term": term}
        if graph_ok:
            m = L.one("Watchlist hits in the live graph", GRAPH,
                "SELECT (SELECT COUNT(*) FROM stable_graph WHERE instr(lower(object), ?) > 0) + "
                "(SELECT COUNT(*) FROM event_graph WHERE instr(lower(object), ?) > 0)", (t, t))
            row["graph"], row["graph_ref"] = m["value"], m["ref"]
            if has_expired:
                m = L.one("Watchlist hits in withdrawn facts", GRAPH,
                    "SELECT (SELECT COUNT(*) FROM expired_stable_graph WHERE instr(lower(object), ?) > 0) + "
                    "(SELECT COUNT(*) FROM expired_event_graph WHERE instr(lower(object), ?) > 0)", (t, t))
                row["withdrawn"], row["withdrawn_ref"] = m["value"], m["ref"]
        if siri_ok:
            m = L.one("Watchlist hits in the interaction log", SIRI,
                "SELECT COUNT(*) FROM entities WHERE instr(lower(COALESCE(id, '')), ?) > 0 "
                "OR instr(lower(COALESCE(fields, '')), ?) > 0", (t, t))
            row["log"], row["log_ref"] = m["value"], m["ref"]
        if cal_ok:
            m = L.one("Watchlist hits in Calendar", CALENDAR,
                "SELECT (SELECT COUNT(*) FROM CalendarItem WHERE instr(lower(COALESCE(summary, '') "
                "|| ' ' || COALESCE(description, '')), ?) > 0) + "
                "(SELECT COUNT(*) FROM Participant WHERE instr(lower(COALESCE(email, '')), ?) > 0)", (t, t))
            row["calendar"], row["calendar_ref"] = m["value"], m["ref"]
        if books:
            total, refs = 0, []
            for rel in books:
                m = L.one("Watchlist hits in Contacts", rel,
                    "SELECT (SELECT COUNT(*) FROM ZABCDEMAILADDRESS WHERE instr(lower(COALESCE(ZADDRESS, '')), ?) > 0) + "
                    "(SELECT COUNT(*) FROM ZABCDRECORD WHERE instr(lower(COALESCE(ZORGANIZATION, '')), ?) > 0)", (t, t))
                total += m["value"] or 0
                refs.append(m["ref"])
            row["contacts"], row["contacts_ref"] = total, ",".join(refs)
        row["total"] = sum(row.get(k) or 0 for k in ("graph", "withdrawn", "log", "calendar", "contacts"))
        rows.append(row)

    searched = [s for s, ok in (("the knowledge graph", graph_ok),
                                ("withdrawn facts", has_expired),
                                ("the interaction log", siri_ok),
                                ("Calendar", cal_ok),
                                ("Contacts", bool(books))) if ok]
    return {"terms": terms, "rows": rows, "searched": searched,
            "not_searched": "Message text in Messages is never searched."}


# ------------------------------------------------------------------ rules

def _finding(fid, severity, title, brief, detail, evidence, impact, actions):
    return {"id": fid, "severity": severity, "title": title, "brief": brief,
            "detail": detail, "evidence": evidence, "impact": impact, "actions": actions}


def _rules(prof, score, comms, apps, prot, watch):
    found, unmeasured = [], []

    # -- people beyond the contact list
    if prof is None:
        unmeasured.append({"area": "People in the graph", "reason": "graph.db could not be read"})
    else:
        people, outside = _v(prof["people"]), _v(prof["people_outside_contacts"])
        photos, unnamed = _v(prof["people_photos"]), _v(prof["people_unnamed"])
        if people and outside:
            from_photos = photos is not None and photos >= outside / 2
            found.append(_finding(
                "F-01", "medium", "The Mac profiles people who were never in the contact list",
                f"{_n(outside)} of the {_n(people)} people in this graph were never in Contacts"
                + ("; most came from faces grouped in Photos." if from_photos else "."),
                "Entities of class person (SB104) with no fact carrying the Contacts source bit. "
                "Photos face clusters are the usual origin; unnamed entities have no name predicate at all.",
                [_ev("People in the graph", prof["people"]),
                 _ev("From the contact list", prof["people_contacts"]),
                 _ev("Never in the contact list", prof["people_outside_contacts"]),
                 _ev("Asserted by Photos face clusters", prof["people_photos"]),
                 _ev("With no name", prof["people_unnamed"]),
                 _ev("Bound to a face cluster", prof["people_faces"])],
                "Bystanders in photos and one-time correspondents become entries. They never agreed "
                "to it and cannot see it. Unnamed entries can still be named later by anyone holding the photos.",
                ["Tell staff that photos taken in sensitive settings feed this store. The Mac drops what "
                 "it learned from a photo on a later run after the photo is deleted."]))

        # -- a ready-made contact network
        reach, emp = _v(prof["people_reachable"]), _v(prof["people_employer"])
        if reach or emp:
            found.append(_finding(
                "F-02", "medium", "Names, numbers and workplaces sit together in one place",
                f"{_n(reach)} people have a phone number or mail address attached, and "
                f"{_n(emp)} have an employer on file.",
                "Distinct person entities carrying a contact-info statement (PS520), an employment "
                "statement (PS500) or a postal address (PS317).",
                [_ev("With a phone number or mail address", prof["people_reachable"]),
                 _ev("With an employer", prof["people_employer"]),
                 _ev("With a postal address", prof["people_address"]),
                 _ev("Organizations", prof["orgs"])],
                "This is the raw material for phishing and impersonation aimed at the owner's circle, "
                "already joined up and searchable.",
                []))

        # -- calendar text
        events, described = _v(prof["events"]), _v(prof["events_described"])
        if events:
            found.append(_finding(
                "F-03", "low", "Calendar entries are copied in, descriptions included",
                f"{_n(events)} calendar events and reservations are in the graph"
                + (f", {_n(described)} with their full description copied word for word." if described else "."),
                "Distinct subjects in event_graph; descriptions are PS51 facts, attendees PS232/PS143.",
                [_ev("Events and reservations", prof["events"]),
                 _ev("With a full description", prof["events_described"]),
                 _ev("Distinct attendees", prof["event_attendees"])],
                "Invite text is often written by someone else and can carry dial-in numbers, agendas and addresses.",
                ["Keep sensitive meeting details out of invite descriptions; put them in a managed document instead."]))

        # -- withdrawn facts
        expired, hours = _v(prof.get("expired")), prof.get("archive_hours")
        if expired:
            found.append(_finding(
                "F-04", "low", "Deleted facts linger for a while",
                f"{_n(expired)} withdrawn facts are still held"
                + (f", reaching back about {hours:g} hours." if hours else "."),
                "Rows in expired_stable_graph and expired_event_graph, kept until "
                "graph_state.expiredTriplesPruneTimestamp. Many are rewrites rather than deletions.",
                [_ev("Withdrawn facts held", prof.get("expired")),
                 {"label": "Archive window, hours", "value": hours, "ref": (prof.get("prune") or {}).get("ref")}],
                "Deleting a contact does not clear it from this store at once.",
                ["When a contact must be removed for someone's safety, allow for the archive window "
                 "before treating the device as clean."]))

        # -- undocumented table
        emb = _v(prof.get("embeddings"))
        n_types = _v(prof.get("embedding_types"))
        if emb:
            found.append(_finding(
                "F-05", "info", "An undocumented embeddings table is in use",
                f"The graph holds {_n(emb)} embedding rows across {_n(n_types)} "
                + ("type." if n_types == 1 else "types."),
                "Table `embeddings (embeddingType, key, embedding BLOB)`. Neither iKnow nor Apple documents it; "
                "the vectors are not decoded here.",
                [_ev("Embedding rows", prof.get("embeddings")),
                 _ev("Embedding types", prof.get("embedding_types"))],
                "Unknown. It is listed so it is tracked across macOS releases, not because it is known to be a risk.",
                []))

    # -- scorecard
    if score is None:
        unmeasured.append({"area": "Relationship scores",
                           "reason": "the scorecard store (entityTagging.db) could not be read"})
    elif _v(score["scored"]):
        orgs = _v(score.get("orgs_scored"))
        found.append(_finding(
            "F-06", "medium", "The Mac scores who is family and who is close",
            f"{_n(_v(score['scored']))} people and organizations carry relationship scores"
            + (f"; {_n(_v(score['with_role']))} were given a specific family role." if score.get("with_role") else "."),
            "Rows in entity_tagging. Score columns are read from the table itself; how the scores are "
            "computed is not documented.",
            [_ev("Entities scored", score["scored"])]
            + ([_ev("Given a specific family role", score["with_role"])] if score.get("with_role") else [])
            + ([_ev("Organizations among the scored", score["orgs_scored"])] if score.get("orgs_scored") else []),
            "The scores are inferred, not recorded, yet they sit beside recorded facts in the same format."
            + (" Organizations are scored too." if orgs else "")
            + " Anyone reading the store gets a ranked list of the people closest to the owner.",
            ["Treat the scorecard as sensitive personal data in any device examination or incident response."]))

    # -- communication log
    if comms is None:
        unmeasured.append({"area": "Communication log",
                           "reason": "the interaction log (siri/remembers/view.db) could not be read"})
    else:
        total = _v(comms["total"])
        pm = comms["by_kind"]["private_messenger"]
        if pm["entries"]:
            found.append(_finding(
                "F-07", "high", "Private messengers leave a contact-by-contact record",
                f"The log holds {_count(pm['entries'], 'entry', 'entries')} from {', '.join(pm['products'])}, covering "
                f"{_count(pm['handles'], 'distinct contact')} and {_count(pm['groups'], 'group')}. It records who, "
                "when and which app; it holds no message text.",
                "Interactions whose bundleId matches the private-messenger rules (appendix). Contacts are "
                "distinct PersonHandle entities; groups are distinct MessageGroup entities.",
                [{"label": "Private-messenger entries", "value": pm["entries"], "ref": comms["refs"]["apps"]},
                 {"label": "Distinct contacts across these apps", "value": pm["handles"], "ref": pm["handles_ref"]},
                 {"label": "Distinct groups across these apps", "value": pm["groups"], "ref": pm["groups_ref"]}],
                "Encryption protects what was said, not the fact of saying it. This is a timing and "
                "frequency record for the very apps people chose for privacy, and the risk falls on their "
                "contacts as much as on them.",
                ["Brief high-risk staff that encrypted apps still leave this local trail.",
                 "Candidate settings, not yet shown to stop new entries: per-app Siri “Learn from this App” "
                 "off; Signal notifications set to No Name or Content and Show Calls in Recents off. "
                 "Test on a spare device before relying on them."]))
        wk = comms["by_kind"]["work_collab"]
        if wk["entries"]:
            found.append(_finding(
                "F-08", "medium", "Work chats map who works with whom",
                f"{_count(wk['entries'], 'entry', 'entries')} from {', '.join(wk['products'])} name "
                f"{_count(wk['groups'], 'chat or group', 'chats or groups')}.",
                "Interactions whose bundleId matches the work-collaboration rules. Group names are counted, "
                "never shown.",
                [{"label": "Work-collaboration entries", "value": wk["entries"], "ref": comms["refs"]["apps"]},
                 {"label": "Distinct chats and groups", "value": wk["groups"], "ref": wk["groups_ref"]},
                 {"label": "Distinct contacts", "value": wk["handles"], "ref": wk["handles_ref"]}],
                "Chat and group names often carry coworkers' names and team names, enough to sketch an "
                "organization chart.",
                ["Keep work and field devices on an Apple Account that is not shared with personal or family devices."]))

        remote = _v(comms.get("remote"))
        if comms["remote_column"] is None:
            unmeasured.append({"area": "Entries from other devices",
                               "reason": "this copy of the log has no device column"})
        elif remote:
            devices = _v(comms.get("remote_devices"))
            share = _pct(remote, total)
            found.append(_finding(
                "F-09", "high", "Activity from other devices lands on this Mac",
                f"{_n(remote)} of {_n(total)} log entries ({share}%) were recorded on "
                + (f"{_n(devices)} other device{'s' if devices != 1 else ''}" if devices else "another device")
                + " on the owner's account and copied here.",
                f"Interactions with a non-empty {comms['remote_column']}. The column identifies the "
                "originating device; device ids are counted, never shown.",
                [_ev("Entries from other devices", comms["remote"]),
                 _ev("Entries in the log", comms["total"])]
                + ([_ev("Other devices feeding the log", comms["remote_devices"])] if comms.get("remote_devices") else []),
                "What happens on one device reaches others on the same Apple Account, including devices "
                "the organization does not manage. Whether it reaches every device on the account was not "
                "tested here.",
                ["Keep work and field devices on an Apple Account that is not shared with personal or family devices."]))
        else:
            found.append(_finding(
                "F-09", "info", "No log entries came from other devices",
                f"None of the {_n(total)} log entries carries another device's id.",
                f"Interactions with a non-empty {comms['remote_column']}: zero.",
                [_ev("Entries from other devices", comms.get("remote")),
                 _ev("Entries in the log", comms["total"])],
                "On this Mac, the log reflects this Mac's own activity.",
                []))

    # -- security stack
    if apps is None:
        unmeasured.append({"area": "Installed apps", "reason": "no app inventory could be read"})
    elif apps["security"]:
        products = sorted({a["product"] for a in apps["security"]})
        has_vpn = any(a["kind"] == "vpn" for a in apps["security"])
        found.append(_finding(
            "F-10", "medium", "The store catalogs the security stack",
            f"The app inventory names {_count(len(products), 'security or management tool', 'security and management tools')}: "
            f"{', '.join(products)}.",
            f"Bundle ids from the {apps['source']} inventory matched against the security rules (appendix).",
            [{"label": "Apps in the inventory", "value": _v(apps["count"]), "ref": apps["ref"]},
             {"label": "Security and management tools", "value": len(products), "ref": apps["ref"]}],
            "Anyone reading the store learns which endpoint protection, management and VPN tools to expect."
            + (" In some countries, a circumvention VPN on a device is itself a risk to the traveler." if has_vpn else ""),
            ["Include the app inventory in travel and device-seizure guidance."]))

    # -- protections
    if not prot.get("measured"):
        unmeasured.append({"area": "FileVault and Full Disk Access", "reason": prot.get("reason")})
    else:
        fv = prot.get("filevault")
        if fv == "off":
            found.append(_finding(
                "F-11", "high", "FileVault is off",
                "The disk is not encrypted, so the store is readable by anyone who removes or boots the drive.",
                "`fdesetup status` reports FileVault is Off.",
                [{"label": "FileVault", "value": "off", "ref": prot["filevault_ref"]}],
                "Every store described in this report is plain SQLite on an unencrypted disk.",
                ["Turn on FileVault now, and enforce it through device management."]))
        elif fv == "on":
            found.append(_finding(
                "F-11", "info", "FileVault is on",
                "The disk is encrypted, so the store is protected while the Mac is off or locked.",
                "`fdesetup status` reports FileVault is On.",
                [{"label": "FileVault", "value": "on", "ref": prot["filevault_ref"]}],
                "Protection ends once someone is logged in: an unlocked Mac reads the store freely.",
                []))
        fda = prot.get("fda")
        if fda is None:
            unmeasured.append({"area": "Full Disk Access list",
                               "reason": "the privacy database could not be read"})
        elif fda:
            found.append(_finding(
                "F-12", "medium", "Apps with Full Disk Access can read all of it",
                (f"1 app holds Full Disk Access on this Mac. It can read every store in this report." if len(fda) == 1 else
                 f"{len(fda)} apps hold Full Disk Access on this Mac. Each one can read every store in this report."),
                "Entries in TCC.db for kTCCServiceSystemPolicyAllFiles with auth_value 2. The app running "
                "iOwl is one of them.",
                [{"label": "Apps with Full Disk Access", "value": len(fda), "ref": prot["fda_ref"]}],
                "One compromised or careless app with this permission exposes the whole store without any exploit.",
                ["Review the list under System Settings › Privacy & Security › Full Disk Access and switch "
                 "off what is not needed, including the app used to run iOwl once the review is done."]))

    # -- watchlist
    if watch["terms"]:
        hits = [r for r in watch["rows"] if r["total"]]
        if hits:
            found.append(_finding(
                "F-13", "medium", "Organization terms appear in the store",
                f"{len(hits)} of {len(watch['terms'])} watchlist terms were found: "
                + "; ".join(f"“{r['term']}” {_n(r['total'])} times" for r in hits) + ".",
                "Case-insensitive substring counts per store (table in the report). Matching values are "
                "counted, never shown.",
                [{"label": f"“{r['term']}”", "value": r["total"],
                  "ref": r.get("graph_ref") or r.get("log_ref") or r.get("calendar_ref")} for r in hits],
                "The organization's footprint on this device is recorded where the graph can join it to people.",
                ["Decide whether these sources (Apple Mail, Calendar, Contacts, messaging) should carry "
                 "work data on this device."]))
        else:
            found.append(_finding(
                "F-13", "info", "No organization terms were found",
                f"None of the {len(watch['terms'])} watchlist terms appears in "
                f"{', '.join(watch['searched']) or 'any readable store'}.",
                "Case-insensitive substring search, counts only.",
                [], "On this device, the stores searched carry no trace of these terms.", []))
    else:
        unmeasured.append({"area": "Organization watchlist",
                           "reason": "no terms were given (add them in watchlist.txt or on the Reports page)"})

    # -- the baseline every report carries
    found.append(_finding(
        "F-14", "info", "The store has no lock of its own",
        "These are ordinary database files. They rely on FileVault and macOS privacy controls, nothing more.",
        "No encryption was found beyond TCC and volume encryption (iKnow agent manual, section 9).",
        [], "An unlocked Mac, or any app with Full Disk Access, reads all of it.",
        ["Keep FileVault on, lock screens quickly, and keep Full Disk Access to a short list."]))

    found.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["id"]))
    return found, unmeasured


# The questions iOwl cannot answer from one Mac's stores. Listed in every report
# so an absence of findings is never read as an all-clear.
OPEN_QUESTIONS = [
    "Whether any of this leaves the Mac. No evidence of upload was found by iKnow's authors; "
    "that is an open question, not a clean result.",
    "Whether backups (Time Machine, iCloud) include these stores.",
    "Whether per-app Siri settings, or messenger notification settings, stop new entries in the log.",
    "Whether log entries reach every device on a shared Apple Account, or only some.",
]


def _actions(found):
    """Every action from the findings, once, most severe first."""
    seen, out = set(), []
    for f in found:
        for a in f["actions"]:
            if a not in seen:
                seen.add(a)
                out.append({"action": a, "severity": f["severity"], "from": f["id"]})
    return out


# ------------------------------------------------------------------ handler

def collect(params=None):
    L = Ledger()
    terms = watch_terms(params)
    prof = _profile(L)
    score = _scorecard(L)
    comms = _comms(L)
    apps = _apps(L)
    prot = _protections(L)
    watch = _watchlist(L, terms)
    found, unmeasured = _rules(prof, score, comms, apps, prot, watch)

    counts = {k: sum(1 for f in found if f["severity"] == k) for k in SEVERITY_ORDER}
    return {
        "version": VERSION,
        "generated": time.time(),
        "mode": "live" if db.live() else "extracted copy",
        "macos": (prot.get("macos") if prot.get("measured") else None),
        "captured": prof.get("captured_unix") if prof else None,
        "stores": _stores(),
        "profile": prof,
        "scorecard": score,
        "comms": comms,
        "apps": apps,
        "protections": prot,
        "watchlist": watch,
        "findings": found,
        "severity_counts": counts,
        "actions": _actions(found),
        "unmeasured": unmeasured,
        "open_questions": OPEN_QUESTIONS,
        "rules": catalog.rules_table(),
        "queries": L.refs,
    }


def handler(params):
    return collect(params)


ROUTES = {"/api/findings": handler}
