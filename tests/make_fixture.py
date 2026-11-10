"""make_fixture.py — a small, entirely made-up Mac, with known answers.

    python3 tests/make_fixture.py /path/to/empty/dir

Builds an extracted-copy layout (graph/, ontology/, sources/) that iOwl reads
with --bundle. Every person, number, address and organization here is invented.
The counts each finding should report are in EXPECTED, and the strings that
must never appear in a report are in SECRETS; tests/test_iowl.py checks both.

This is the only code in iOwl that writes files, and it writes only invented
data into the directory it is given.
"""

import os
import sqlite3
import sys

COLS = ("subject INTEGER, predicate TEXT, relationshipId INTEGER, relationshipPredicate TEXT, "
        "object TEXT, sources INTEGER, confidence DOUBLE, sourceDuplicates TEXT, timestamp DOUBLE")

CAPTURED = 800000000.0          # Apple time of the newest write
PRUNE = CAPTURED - 24 * 3600    # a 24-hour withdrawal archive

C, P = 1, 32                    # Contacts and Photos source bits

PEOPLE = {  # id: (first, family, phone or None, employer org or None)
    2: ("Alice", "Fixture", "+1 555 0100 201", 100),
    3: ("Bram", "Fixture", "+1 555 0100 202", 100),
    4: ("Chidi", "Example", "+1 555 0100 203", 101),
    5: ("Dana", "Sample", "+1 555 0100 204", 101),
    6: ("Eitan", "Placeholder", "+1 555 0100 205", None),
    7: ("Farah", "Madeup", "+1 555 0100 206", None),
    8: ("Goran", "Invented", "+1 555 0100 207", None),
    9: ("Hana", "Notreal", None, None),
    10: ("Ivo", "Testcase", None, None),
    11: ("Juno", "Stubbs", None, None),
}
FACES = (12, 13, 14, 15, 16)    # people known only from Photos, unnamed

SECRETS = (["Owner Person"] + [f"{f} {l}" for f, l, _p, _o in PEOPLE.values()]
           + [p for _f, _l, p, _o in PEOPLE.values() if p]
           + ["p4@example.org", "1 Fixture Lane", "+44 7700 900123", "+44 7700 900456",
              "+44 7700 900789", "+44 7700 900111", "+44 7700 900222", "a@example.org",
              "c@example.org", "Signal Group Secret", "Hidden Dinner Plan"])

EXPECTED = {
    "people": 16, "people_contacts": 11, "people_outside_contacts": 5, "people_photos": 5,
    "people_unnamed": 5, "people_faces": 5, "people_reachable": 7, "people_employer": 4,
    "people_address": 1, "orgs": 2, "places": 1, "events": 3, "events_described": 1,
    "event_attendees": 2, "expired": 3, "embeddings": 4, "embedding_types": 2,
    "archive_hours": 24.0,
    "log_total": 18, "pm_entries": 10, "pm_handles": 4, "pm_groups": 1,
    "work_entries": 3, "work_groups": 2, "remote": 4, "remote_devices": 2,
    "scored": 8, "with_role": 2, "orgs_scored": 1,
    "apps": 5, "security_products": ["Company Portal (Intune)", "CrowdStrike Falcon", "Tor Browser"],
    "watch": {"example.org": {"graph": 2, "withdrawn": 0, "log": 0, "calendar": 2, "contacts": 1, "total": 5},
              "acme mission": {"graph": 1, "withdrawn": 0, "log": 1, "calendar": 0, "contacts": 1, "total": 3}},
}


def _db(path, ddl):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path):
        os.remove(path)
    conn = sqlite3.connect(path)
    conn.executescript(ddl)
    return conn


def graph(base):
    conn = _db(os.path.join(base, "graph", "graph.db"), f"""
        CREATE TABLE stable_graph ({COLS});
        CREATE TABLE event_graph ({COLS});
        CREATE TABLE expired_stable_graph ({COLS});
        CREATE TABLE expired_event_graph ({COLS});
        CREATE TABLE graph_state (key TEXT PRIMARY KEY, value ANY);
        CREATE TABLE embeddings (embeddingType TEXT NOT NULL, key TEXT NOT NULL, embedding BLOB NOT NULL,
                                 PRIMARY KEY (embeddingType, key));
    """)
    rows, ev, rid = [], [], [1000]

    def add(table, s, p, o, src=C, rel=0, rp="", conf=1.0, ts=CAPTURED - 100):
        table.append((s, p, rel, rp, o, src, conf, "x", ts))

    def stmt(table, s, p, facets, src=C):
        rid[0] += 1
        for fp, fo in facets:
            add(table, s, p, fo, src, rid[0], fp)

    # the owner
    add(rows, 1, "PS1", "SB104")
    add(rows, 1, "nm_isCurrentUser", "1")
    add(rows, 1, "PS33", "Owner Person", ts=CAPTURED)
    # people from Contacts
    for pid, (first, family, phone, org) in PEOPLE.items():
        add(rows, pid, "PS1", "SB104")
        add(rows, pid, "PS33", f"{first} {family}")
        if phone:
            facets = [("PS1", "CS97"), ("PS407", phone), ("PS740", "_$!<Mobile>!$_")]
            if pid == 4:
                facets.append(("PS406", "p4@example.org"))
            stmt(rows, pid, "PS520", facets)
        if org:
            stmt(rows, pid, "PS500", [("PS45", f"md:{org}")])
    stmt(rows, 2, "PS317", [("PS316", "1 Fixture Lane"), ("PS453", "Nowhere")])
    # people known only from Photos
    for pid in FACES:
        add(rows, pid, "PS1", "SB104", src=P, conf=0.9)
        stmt(rows, pid, "nm_hasVisualIdentifier",
             [("nm_visualIdentifier", f"00000000-0000-0000-0000-0000000000{pid}/L0/040")], src=P)
    # organizations, a place, apps
    add(rows, 100, "PS1", "SB10"); add(rows, 100, "PS33", "Acme Mission")
    add(rows, 101, "PS1", "SB10"); add(rows, 101, "PS33", "Example Org")
    add(rows, 200, "PS1", "SB152", src=1 << 10, conf=0.8)
    for i, b in enumerate(("com.crowdstrike.falcon.Agent", "com.microsoft.CompanyPortalMac",
                           "org.torproject.torbrowser", "com.apple.Safari", "com.example.notes")):
        add(rows, 300 + i, "PS1", "SB144", src=1 << 15, conf=0.8)
        add(rows, 300 + i, "nm_bundleID", b, src=1 << 15, conf=0.8)
    # events
    for eid, title in ((500, "Hidden Dinner Plan"), (501, "Weekly sync"), (502, "Flight")):
        add(ev, eid, "PS1", "SB472", src=1 << 8)
        add(ev, eid, "PS33", title, src=1 << 8)
    add(ev, 500, "PS51", "Dial in at example.org/join", src=1 << 11, conf=0.8)
    stmt(ev, 500, "PS232", [("PS143", "md:2")], src=1 << 8)
    stmt(ev, 500, "PS232", [("PS143", "md:3")], src=1 << 8)
    stmt(ev, 501, "PS232", [("PS143", "md:2")], src=1 << 8)

    conn.executemany("INSERT INTO stable_graph VALUES (?,?,?,?,?,?,?,?,?)", rows)
    conn.executemany("INSERT INTO event_graph VALUES (?,?,?,?,?,?,?,?,?)", ev)
    conn.executemany("INSERT INTO expired_stable_graph VALUES (?,?,?,?,?,?,?,?,?)",
                     [(9, "PS33", 0, "", "Old Name", C, 1.0, "x", PRUNE + 10),
                      (9, "PS740", 0, "", "home", C, 1.0, "x", PRUNE + 20)])
    conn.execute("INSERT INTO expired_event_graph VALUES (502, 'PS33', 0, '', 'Old flight', 256, 1.0, 'x', ?)",
                 (PRUNE + 30,))
    conn.executemany("INSERT INTO graph_state VALUES (?, ?)",
                     [("expiredTriplesPruneTimestamp", PRUNE), ("buildFromScratchTimestamp", PRUNE - 9e5)])
    conn.executemany("INSERT INTO embeddings VALUES (?, ?, ?)",
                     [("person", "a", b"\0" * 8), ("person", "b", b"\0" * 8),
                      ("place", "c", b"\0" * 8), ("place", "d", b"\0" * 8)])
    conn.commit()
    conn.close()


def siri(base):
    conn = _db(os.path.join(base, "graph", "Artifacts__siri__remembers__view.db"), """
        CREATE TABLE interactions (domain TEXT, bundleId TEXT, direction INTEGER, handlingStatus INTEGER,
            startDate DOUBLE, durationSeconds DOUBLE, contentHash TEXT, isLocal INTEGER,
            remoteDeviceId TEXT, fields TEXT, type TEXT);
        CREATE TABLE entities (type TEXT, id TEXT, fields TEXT);
        CREATE TABLE interactionEntities (interactionRowid INTEGER, entityRowid INTEGER, parameter TEXT);
    """)
    ents = {}

    def ent(etype, eid, name=None):
        key = (etype, eid)
        if key not in ents:
            fields = '{"name": "%s"}' % name if name else "{}"
            cur = conn.execute("INSERT INTO entities VALUES (?, ?, ?)", (etype, eid, fields))
            ents[key] = cur.lastrowid
        return ents[key]

    t = [CAPTURED - 86400 * 200]

    def log(bundle, domain, handle=None, group=None, remote=None):
        t[0] += 3600
        cur = conn.execute("INSERT INTO interactions VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                           (domain, bundle, 1, 3, t[0], 0, "th", 0 if remote else 1, remote, "{}", "x"))
        iid = cur.lastrowid
        if handle:
            conn.execute("INSERT INTO interactionEntities VALUES (?, ?, 'recipients')",
                         (iid, ent("PersonHandle", handle)))
        if group:
            conn.execute("INSERT INTO interactionEntities VALUES (?, ?, 'recipients')",
                         (iid, ent("MessageGroup", "g:" + group, group)))

    s = "org.whispersystems.signal"
    for h in ("+44 7700 900123", "+44 7700 900456", "+44 7700 900789", "+44 7700 900123", "+44 7700 900456"):
        log(s, "Messages", handle=h)
    log(s, "Messages", group="Signal Group Secret", remote="devA")
    w = "net.whatsapp.WhatsApp"
    for h, r in (("+44 7700 900123", None), ("+44 7700 900111", "devA"),
                 ("+44 7700 900111", None), ("+44 7700 900123", "devB")):
        log(w, "Messages", handle=h, remote=r)
    for g, r in (("Acme Mission Field Team", None), ("Ops", None), ("Ops", "devB")):
        log("com.microsoft.teams2", "Messages", group=g, remote=r)
    for h in ("+44 7700 900222", "+44 7700 900222", "+1 555 0100 201", "+1 555 0100 202", "+1 555 0100 203"):
        log("com.apple.MobileSMS", "Messages", handle=h)
    conn.commit()
    conn.close()


def tagging(base):
    conn = _db(os.path.join(base, "graph", "Artifacts__entityTagging__entityTagging.db"), """
        CREATE TABLE entity_tagging (mdid TEXT PRIMARY KEY, familyAndFriends DOUBLE, family DOUBLE,
            friend DOUBLE, partner DOUBLE, mother DOUBLE, father DOUBLE, sibling DOUBLE, child DOUBLE,
            myself DOUBLE);
    """)
    rows = [(str(i), 0.9, 0.6, 0.3, 0, 0, 0, 0, 0, 0) for i in range(2, 9)] + [("100", 0.8, 0.7, 0, 0, 0, 0, 0, 0, 0)]
    rows[0] = ("2", 0.99, 0.9, 0.1, 0.5, 0, 0, 0, 0, 0)
    rows[1] = ("3", 0.95, 0.9, 0.1, 0, 0.25, 0, 0, 0, 0)
    conn.executemany("INSERT INTO entity_tagging VALUES (?,?,?,?,?,?,?,?,?,?)", rows)
    conn.commit()
    conn.close()


def calendar(base):
    conn = _db(os.path.join(base, "sources", "Calendar.sqlitedb"), """
        CREATE TABLE Store (ROWID INTEGER PRIMARY KEY, persistent_id TEXT);
        CREATE TABLE Calendar (ROWID INTEGER PRIMARY KEY, store_id INTEGER);
        CREATE TABLE CalendarItem (ROWID INTEGER PRIMARY KEY, summary TEXT, description TEXT,
                                   calendar_id INTEGER, unique_identifier TEXT, start_date DOUBLE);
        CREATE TABLE Participant (ROWID INTEGER PRIMARY KEY, owner_id INTEGER, email TEXT);
    """)
    conn.execute("INSERT INTO CalendarItem VALUES (1, 'Hidden Dinner Plan', 'Agenda at example.org', 1, 'u1', 0)")
    conn.execute("INSERT INTO CalendarItem VALUES (2, 'Weekly sync', '', 1, 'u2', 0)")
    conn.execute("INSERT INTO Participant VALUES (1, 1, 'a@example.org')")
    conn.execute("INSERT INTO Participant VALUES (2, 2, 'someone@else.test')")
    conn.commit()
    conn.close()


def contacts(base):
    conn = _db(os.path.join(base, "sources", "AddressBook", "ABCD1234-0000.abcddb"), """
        CREATE TABLE ZABCDRECORD (Z_PK INTEGER PRIMARY KEY, ZFIRSTNAME TEXT, ZLASTNAME TEXT,
                                  ZORGANIZATION TEXT, ZUNIQUEID TEXT, ZLINKID TEXT, ZNICKNAME TEXT);
        CREATE TABLE ZABCDEMAILADDRESS (Z_PK INTEGER PRIMARY KEY, ZOWNER INTEGER, ZADDRESS TEXT);
        CREATE TABLE ZABCDPHONENUMBER (Z_PK INTEGER PRIMARY KEY, ZOWNER INTEGER, ZFULLNUMBER TEXT);
        CREATE TABLE ZABCDPOSTALADDRESS (Z_PK INTEGER PRIMARY KEY, ZOWNER INTEGER, ZSTREET TEXT, ZCITY TEXT);
    """)
    conn.execute("INSERT INTO ZABCDRECORD VALUES (1, 'Alice', 'Fixture', 'Acme Mission', 'u-1:ABPerson', NULL, NULL)")
    conn.execute("INSERT INTO ZABCDRECORD VALUES (2, 'Bram', 'Fixture', NULL, 'u-2:ABPerson', NULL, NULL)")
    conn.execute("INSERT INTO ZABCDEMAILADDRESS VALUES (1, 2, 'c@example.org')")
    conn.execute("INSERT INTO ZABCDPHONENUMBER VALUES (1, 1, '+1 555 0100 201')")
    conn.commit()
    conn.close()


def ontology(base):
    os.makedirs(os.path.join(base, "ontology"), exist_ok=True)
    with open(os.path.join(base, "ontology", "predicate.json"), "w") as fh:
        fh.write('{"predicates": [{"predicateId": "PS33", "label": "name"}, '
                 '{"predicateId": "PS520", "label": "contact info"}]}')
    with open(os.path.join(base, "ontology", "class.json"), "w") as fh:
        fh.write('{"classes": [{"classId": "SB104", "label": "person"}, '
                 '{"classId": "SB10", "label": "organization"}]}')


def build(base):
    graph(base)
    siri(base)
    tagging(base)
    calendar(base)
    contacts(base)
    ontology(base)
    return base


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: make_fixture.py <empty directory>")
    print(build(os.path.abspath(sys.argv[1])))
