"""messaging.py — one page per messenger: what the stores keep about Signal,
WhatsApp, Messages and the rest, side by side.

Four sources, all read-only, none holding a message body except the last:

  installed   the graph's application entities (nm_bundleID) and the Biome
              App.InstalledApp set
  history     Siri's interaction log: messages and calls, sent and received,
              group chats, the people and handles named, the devices it came from
  pairings    Siri's resolver: which contact it pairs with which app
  chat.db     Messages' own database, which is the only place that says whether
              a message went by iMessage, SMS or RCS. Counts only; no text is read.

Direction is read per interaction from who is listed on it. A row naming a
sender (or senderHandle) was received; a row naming only recipients was sent.
Calls name the other party in a `contacts` slot, so for a row with neither the
direction column decides, read with the sender test in comms.direction_values,
extended here to senderHandle. Apple's documented numbering is not assumed.

People and group chat names are in the payload. The share-safe switch replaces
both: people through the usual harvest, group chats because redact.py now
harvests the MessageGroup names and Messages' chat names as their own kind.
"""

import json

from . import biome, db, vocab

STORE = "graph/Artifacts__siri__remembers__view.db"
RESOLVER = "graph/Artifacts__siri__defaultResolverInteractions__view.db"
VIEWS = "graph/Artifacts__internal__views.db"
GRAPH = "graph/graph.db"
CHAT = "sources/chat.db"

PRIVATE = "Private or encrypted messenger"
APPLE = "Apple Messages, Phone and FaceTime"
SOCIAL = "Social and community chat"
WORK = "Work collaboration"
KIND_ORDER = [PRIVATE, APPLE, SOCIAL, WORK]

# key, product, kind, bundle-id prefixes (lower case), always listed
APPS = [
    ("signal", "Signal", PRIVATE, ["org.whispersystems.signal"], True),
    ("whatsapp", "WhatsApp", PRIVATE, ["net.whatsapp.", "desktop.whatsapp", "whatsapp"], True),
    ("messages", "Messages (iMessage, SMS and RCS)", APPLE,
     ["com.apple.mobilesms", "com.apple.ichat", "com.apple.messages"], True),
    ("telegram", "Telegram", PRIVATE, ["ph.telegra.", "org.telegram.", "ru.keepcoder.telegram"], True),
    ("phone", "Phone calls", APPLE,
     ["com.apple.incallservice", "com.apple.mobilephone", "com.apple.telephonyutilities"], True),
    ("facetime", "FaceTime", APPLE, ["com.apple.facetime"], True),
    ("messenger", "Facebook Messenger", SOCIAL, ["com.facebook.messenger"], True),
    ("threema", "Threema", PRIVATE, ["ch.threema."], False),
    ("wire", "Wire", PRIVATE, ["com.wire.", "com.wearezeta."], False),
    ("element", "Element", PRIVATE, ["im.vector.", "im.riot.", "io.element."], False),
    ("session", "Session", PRIVATE, ["com.sessionmessenger.", "com.loki-project."], False),
    ("simplex", "SimpleX", PRIVATE, ["chat.simplex."], False),
    ("viber", "Viber", PRIVATE, ["com.viber."], False),
    ("line", "LINE", SOCIAL, ["jp.naver.line"], False),
    ("wechat", "WeChat", SOCIAL, ["com.tencent.xin"], False),
    ("kakao", "KakaoTalk", SOCIAL, ["com.iwilab.kakaotalk"], False),
    ("facebook", "Facebook", SOCIAL, ["com.facebook.facebook"], False),
    ("instagram", "Instagram", SOCIAL, ["com.burbn.instagram"], False),
    ("snapchat", "Snapchat", SOCIAL, ["com.toyopagroup.picaboo"], False),
    ("discord", "Discord", SOCIAL, ["com.hammerandchisel.discord", "com.hnc.discord", "com.discord"], False),
    ("x", "X", SOCIAL, ["com.atebits.tweetie2"], False),
    ("linkedin", "LinkedIn", SOCIAL, ["com.linkedin."], False),
    ("teams", "Microsoft Teams", WORK, ["com.microsoft.teams", "com.microsoft.skype.teams"], False),
    ("skype", "Skype", WORK, ["com.skype."], False),
    ("slack", "Slack", WORK, ["com.tinyspeck.", "com.slack."], False),
    ("zoom", "Zoom", WORK, ["us.zoom."], False),
    ("webex", "Webex", WORK, ["com.cisco.webex", "com.webex."], False),
    ("googlechat", "Google Chat", WORK, ["com.google.dynamite", "com.google.chat"], False),
]

TOP_PEOPLE = 25
TOP_GROUPS = 25

NOTHING = ("No trace in these stores. That can mean the app is not on your devices, that it does not "
           "hand its activity to Siri, or that its Siri setting is off. These stores cannot tell which.")
IMESSAGE = ("Siri's history counts iMessage, SMS and RCS together as Messages. The split by service "
            "below comes from Messages' own database on this Mac.")

PEOPLE_PARAMS = ("sender", "senderHandle", "recipients", "recipientHandles", "contacts", "contactHandles")


def app_of(bundle):
    b = (bundle or "").lower()
    for key, _, _, prefixes, _ in APPS:
        if any(b.startswith(p) for p in prefixes):
            return key
    return None


def _handle(h):
    """A handle as the stores spell it, normalised for joining: the last ten
    digits of a number, or the lower-cased mail address."""
    if not isinstance(h, str) or not h.strip():
        return None
    h = h.strip()
    if h.lower().startswith(("mailto:", "tel:")):
        h = h.split(":", 1)[1]
    if "@" in h:
        return h.lower()
    d = "".join(c for c in h if c.isdigit())
    return d[-10:] if len(d) >= 7 else None


def _day(t):
    ts = db.apple_time(t)
    if ts is None:
        return None
    import time
    return time.strftime("%Y-%m-%d", time.gmtime(ts))


def _field(fields, key):
    try:
        return json.loads(fields or "{}").get(key)
    except (TypeError, ValueError, AttributeError):
        return None


def _cols(rel, table):
    return {r["name"] for r in db.query(rel, 'pragma table_info("%s")' % table)}


def _directions():
    """(incoming, outgoing) by the sender test, counting senderHandle as a sender."""
    if "direction" not in _cols(STORE, "interactions"):
        return None, None
    rs = db.query(STORE, """
        select i.direction as v,
               sum(exists(select 1 from interactionEntities x where x.interactionRowid=i.rowid
                          and x.parameter in ('sender','senderHandle'))) as s,
               sum(exists(select 1 from interactionEntities x where x.interactionRowid=i.rowid
                          and x.parameter in ('recipients','recipientHandles','contacts','contactHandles'))) as r
        from interactions i group by 1""")
    carriers = [r for r in rs if (r["s"] or 0) > 0]
    inc = max(carriers, key=lambda r: r["s"])["v"] if carriers else None
    others = [r for r in rs if r["v"] != inc and (r["r"] or 0) > 0]
    out = max(others, key=lambda r: r["r"])["v"] if others else None
    return inc, out


def _blank(key, product, kind, watch):
    return {"key": key, "product": product, "kind": kind, "watch": watch, "bundles": set(),
            "installed": set(), "interactions": 0, "messages": 0, "calls": 0, "other": 0,
            "sent": 0, "received": 0, "requests": 0, "in_groups": 0, "groups": set(),
            "people": set(), "named": set(), "devices": set(), "on_mac": 0,
            "first": None, "last": None, "pairings": 0, "pairing_events": 0,
            "by_person": {}, "by_group": {}}


def _installed(A):
    for r in db.query(GRAPH, "select distinct object as b from stable_graph where predicate='nm_bundleID'") \
            if db.has_table(GRAPH, "stable_graph") else []:
        k = app_of(r["b"])
        if k:
            A[k]["installed"].add(r["b"])
            A[k]["bundles"].add(r["b"])
    try:
        apps, _ = biome.installed_apps()
    except Exception:  # the Biome set is optional; its absence is on the ledger already
        apps = []
    for a in apps:
        k = app_of(a.get("bundle"))
        if k:
            A[k]["installed"].add(a["bundle"])
            A[k]["bundles"].add(a["bundle"])


def _history(A):
    if not db.has_table(STORE, "interactions"):
        return False, {}
    owner = vocab.owner_id()
    hmap = {}
    if db.has_table(VIEWS, "handle_id"):
        for r in db.query(VIEWS, "select handle, id from handle_id"):
            n = _handle(r["handle"])
            try:
                eid = int(r["id"])
            except (TypeError, ValueError):
                continue
            if n and eid != owner:
                hmap.setdefault(n, set()).add(eid)
    ents = {r["rowid"]: r for r in db.query(
        STORE, "select rowid, id, type, fields from entities "
               "where type in ('Person','PersonHandle','MessageGroup')")}
    params = {}
    for r in db.query(STORE, "select interactionRowid i, entityRowid e, parameter p from interactionEntities"):
        params.setdefault(r["i"], []).append((r["e"], r["p"]))
    inc, outg = _directions()
    have = _cols(STORE, "interactions")
    dcol = "direction" if "direction" in have else "null"
    dev = "coalesce(nullif(remoteDeviceId,''),'')" if "remoteDeviceId" in have else "''"
    for r in db.query(STORE, "select rowid, type, bundleId, startDate t, %s dev, %s dir from interactions"
                             % (dev, dcol)):
        k = app_of(r["bundleId"])
        if not k:
            continue
        a, t = A[k], r["t"]
        a["bundles"].add(r["bundleId"])
        a["interactions"] += 1
        if r["type"] == "INSendMessageIntent":
            a["messages"] += 1
        elif r["type"] == "INStartCallIntent":
            a["calls"] += 1
        else:
            a["other"] += 1
        if r["dev"]:
            a["devices"].add(r["dev"])
        else:
            a["on_mac"] += 1
        if t is not None:
            a["first"] = t if a["first"] is None else min(a["first"], t)
            a["last"] = t if a["last"] is None else max(a["last"], t)
        ps = params.get(r["rowid"], [])
        names = [p for _, p in ps]
        if any(p.startswith("sender") for p in names):
            way = "received"
        elif any(p.startswith("recipient") for p in names):
            way = "sent"
        elif inc is not None and r["dir"] == inc:
            way = "received"
        elif outg is not None and r["dir"] == outg:
            way = "sent"
        else:
            way = "requests"
        a[way] += 1
        group = None
        for erow, p in ps:
            e = ents.get(erow)
            if not e:
                continue
            if e["type"] == "MessageGroup":  # speakableGroupName on current macOS
                group = erow
                a["groups"].add(erow)
            elif e["type"] in ("Person", "PersonHandle") and p in PEOPLE_PARAMS:
                a["people"].add(erow)
                pids = hmap.get(_handle(e["id"])) if e["type"] == "PersonHandle" else None
                if pids:
                    a["named"] |= pids
                key = ("pid", tuple(sorted(pids))) if pids else ("ent", erow)
                c = a["by_person"].setdefault(key, {"sent": 0, "received": 0, "other": 0, "last": None,
                                                    "fields": e["fields"], "eid": e["id"]})
                mine = ("received" if p.startswith("sender") else "sent" if p.startswith("recipient")
                        else way if way in ("sent", "received") else "other")
                c[mine] += 1
                if t is not None:
                    c["last"] = t if c["last"] is None else max(c["last"], t)
        if group is not None:
            a["in_groups"] += 1
            g = a["by_group"].setdefault(group, {"count": 0, "last": None})
            g["count"] += 1
            if t is not None:
                g["last"] = t if g["last"] is None else max(g["last"], t)
    groups = {rid: (_field(e["fields"], "name") or None) for rid, e in ents.items() if e["type"] == "MessageGroup"}
    return True, groups


def _pairings(A):
    if not (db.has_table(RESOLVER, "candidates") and db.has_table(RESOLVER, "tupleCandidates")):
        return False
    for r in db.query(RESOLVER, "select c.bundleId b, count(distinct tc.tupleId) n from tupleCandidates tc "
                                "join candidates c on c.id=tc.candidateId where c.bundleId != '' group by 1"):
        k = app_of(r["b"])
        if k:
            A[k]["pairings"] += r["n"] or 0
            A[k]["bundles"].add(r["b"])
    if db.has_table(RESOLVER, "tupleInteractions"):
        for r in db.query(RESOLVER, "select c.bundleId b, count(*) n from tupleInteractions ti "
                                    "join tupleCandidates tc on tc.tupleId=ti.tupleId "
                                    "join candidates c on c.id=tc.candidateId where c.bundleId != '' group by 1"):
            k = app_of(r["b"])
            if k:
                A[k]["pairing_events"] += r["n"] or 0
    return True


def _chat_db():
    """Messages' own database, split by service. Counts only: no text column is read."""
    if not db.has_table(CHAT, "message"):
        return None
    mc = _cols(CHAT, "message")
    if "service" not in mc:
        return None
    mine = "is_from_me" if "is_from_me" in mc else "null"
    date = "date" if "date" in mc else "null"
    svc = {}
    for r in db.query(CHAT, "select coalesce(service,'(none)') s, %s me, count(*) n, min(nullif(%s,0)) a, "
                            "max(%s) b from message group by 1, 2" % (mine, date, date)):
        x = svc.setdefault(r["s"], {"service": r["s"], "messages": 0, "sent": 0, "received": 0,
                                    "chats": 0, "group_chats": 0, "handles": 0, "first": None, "last": None})
        x["messages"] += r["n"]
        if r["me"] == 1:
            x["sent"] += r["n"]
        elif r["me"] == 0:
            x["received"] += r["n"]
        for f, v, pick in (("first", r["a"], min), ("last", r["b"], max)):
            if v is not None:
                x[f] = v if x[f] is None else pick(x[f], v)
    if db.has_table(CHAT, "chat") and "service_name" in _cols(CHAT, "chat"):
        style = "style=43" if "style" in _cols(CHAT, "chat") else "0"
        for r in db.query(CHAT, "select coalesce(service_name,'(none)') s, count(*) n, sum(%s) g "
                                "from chat group by 1" % style):
            x = svc.setdefault(r["s"], {"service": r["s"], "messages": 0, "sent": 0, "received": 0,
                                        "chats": 0, "group_chats": 0, "handles": 0, "first": None, "last": None})
            x["chats"], x["group_chats"] = r["n"], r["g"] or 0
    if db.has_table(CHAT, "handle") and "service" in _cols(CHAT, "handle"):
        for r in db.query(CHAT, "select coalesce(service,'(none)') s, count(*) n from handle group by 1"):
            if r["s"] in svc:
                svc[r["s"]]["handles"] = r["n"]
    out = sorted(svc.values(), key=lambda x: -x["messages"])
    for x in out:
        x["first"], x["last"] = _day(x["first"]), _day(x["last"])
    return {"store": CHAT, "services": out,
            "messages": sum(x["messages"] for x in out)}


def _n(n, one, many=None):
    return "%d %s" % (n, one if n == 1 else (many or one + "s"))


def _status(a, measured):
    if a["interactions"]:
        return "logged"
    if a["installed"] or a["pairings"]:
        return "present, nothing logged"
    return "no trace" if measured else "not measured"


def _story(a, measured):
    s = []
    if not measured:
        s.append("Siri's history could not be read, so activity is not measured.")
    if a["interactions"]:
        where = []
        if a["devices"]:
            where.append("from %s" % _n(len(a["devices"]), "other device"))
        if a["on_mac"]:
            where.append("%d from this Mac" % a["on_mac"])
        s.append("Siri's history on this Mac holds %s for %s between %s and %s, %s." % (
            _n(a["interactions"], "interaction"), a["product"], _day(a["first"]), _day(a["last"]),
            ", ".join(where)))
        parts = [x for x in (_n(a["messages"], "message") if a["messages"] else None,
                             _n(a["calls"], "call") if a["calls"] else None,
                             _n(a["other"], "other request") if a["other"] else None) if x]
        tail = ", and %d with no direction" % a["requests"] if a["requests"] else ""
        s.append("That is %s: %d outgoing and %d incoming%s." % (" and ".join(parts), a["sent"], a["received"], tail))
        if a["received"] and not a["sent"]:
            s.append("Every row is incoming. Nothing you sent in %s reached these stores, only what you received."
                     % a["product"])
        elif a["sent"] and not a["received"]:
            s.append("Every row is outgoing. Nothing you received in %s reached these stores." % a["product"])
        if a["groups"]:
            share = round(100.0 * a["in_groups"] / a["interactions"])
            s.append("%d%% of it is in %s. Siri keeps each group's name." % (share, _n(len(a["groups"]), "group chat")))
        elif a["messages"]:
            s.append("None of it is tagged to a group chat.")
        s.append("It names %s; %d of them resolve to a person in the knowledge graph." % (
            _n(len(a["people"]), "person or handle", "people or handles"), len(a["named"])))
    if a["pairings"]:
        s.append("Siri holds %s pairing a contact with %s, used %d times. That is its record of which app "
                 "you use for whom." % (_n(a["pairings"], "pairing"), a["product"], a["pairing_events"]))
    if a["installed"]:
        s.append("Installed on this Mac.")
    if not (a["interactions"] or a["pairings"]):
        s.append(NOTHING if not a["installed"] else
                 "Installed, but nothing it did reached these stores. It may not hand its activity to Siri, "
                 "or its Siri setting may be off. These stores cannot tell which.")
    return s


def _people(a, names):
    rows = {}
    for key, c in a["by_person"].items():
        if key[0] == "pid":
            label = " / ".join(sorted({names.get(p) or "unnamed person #%s" % p for p in key[1]}))
            ids = list(key[1])
        else:
            label = _field(c["fields"], "name") or c["eid"] or "unnamed handle"
            ids = []
        m = rows.setdefault(label, {"name": label, "ids": ids, "resolved": bool(ids),
                                    "sent": 0, "received": 0, "other": 0, "total": 0, "last": None})
        for f in ("sent", "received", "other"):
            m[f] += c[f]
            m["total"] += c[f]
        if c["last"] is not None:
            m["last"] = c["last"] if m["last"] is None else max(m["last"], c["last"])
    out = sorted(rows.values(), key=lambda x: -x["total"])
    for x in out:
        x["last"] = _day(x["last"])
    return out[:TOP_PEOPLE], len(out)


def handler(params):
    A = {k: _blank(k, p, kd, w) for k, p, kd, _, w in APPS}
    _installed(A)
    measured, groups = _history(A)
    paired = _pairings(A)
    names = vocab.names()
    chat = _chat_db()

    apps = []
    for a in A.values():
        seen = bool(a["installed"] or a["interactions"] or a["pairings"])
        if not (seen or a["watch"]):
            continue
        people, people_total = _people(a, names)
        grp = sorted(({"name": groups.get(g) or "unnamed group chat #%s" % g, "count": v["count"],
                       "last": _day(v["last"])} for g, v in a["by_group"].items()),
                     key=lambda x: -x["count"])
        app = {
            "key": a["key"], "product": a["product"], "kind": a["kind"], "watch": a["watch"], "seen": seen,
            "installed": bool(a["installed"]), "bundles": sorted(a["bundles"]),
            "interactions": a["interactions"], "messages": a["messages"], "calls": a["calls"], "other": a["other"],
            "sent": a["sent"], "received": a["received"], "requests": a["requests"],
            "in_groups": a["in_groups"], "group_chats": len(a["groups"]),
            "people": len(a["people"]), "named": len(a["named"]),
            "other_devices": len(a["devices"]), "from_this_mac": a["on_mac"],
            "first": _day(a["first"]), "last": _day(a["last"]),
            "pairings": a["pairings"], "pairing_events": a["pairing_events"],
            "status": _status(a, measured), "story": _story(a, measured),
            "top_people": people, "people_listed": len(people), "people_total": people_total,
            "groups": grp[:TOP_GROUPS], "groups_total": len(grp),
        }
        if a["key"] == "messages":
            app["note"] = IMESSAGE
            app["services"] = chat
        apps.append(app)
    apps.sort(key=lambda x: (not x["watch"] and not x["interactions"], KIND_ORDER.index(x["kind"]),
                             -x["interactions"]))

    logged = [x for x in apps if x["interactions"]]
    total = sum(x["interactions"] for x in apps)
    priv = [x for x in logged if x["kind"] == PRIVATE]
    quiet = [x["product"] for x in apps if x["watch"] and not x["seen"]]
    if measured:
        headline = "Siri's history on this Mac holds %d messaging and calling interactions across %s." % (
            total, _n(len(logged), "app"))
        if priv:
            headline += " Private messengers: " + ", ".join(
                "%s %d" % (x["product"], x["interactions"]) for x in priv) + "."
        if quiet:
            headline += " No trace of " + ", ".join(quiet) + "."
    else:
        headline = "Siri's history could not be read, so messaging activity is not measured."
    inc, outg = _directions() if measured else (None, None)
    return {
        "present": measured or bool(chat),
        "headline": headline,
        "apps": apps,
        "kinds": KIND_ORDER,
        "sources": {"history": STORE if measured else None, "pairings": RESOLVER if paired else None,
                    "chat": CHAT if chat else None},
        "direction": {"incoming": inc, "outgoing": outg},
        "caps": {"people": TOP_PEOPLE, "groups": TOP_GROUPS},
        "nothing": NOTHING,
    }


ROUTES = {"/api/messaging": handler}
