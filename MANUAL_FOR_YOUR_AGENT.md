# iOwl guide for AI agents

This guide is for an AI agent with a shell on a Mac whose owner wants to know
what macOS's personal knowledge graph holds about them. Read section 1 and do
what it says before anything else. Read section 9 before you write a query.

Apple does not document these stores and changes them between releases. The
details below were checked on macOS 26 and 27. Confirm any table or column with
`.schema` before you rely on it. Every id, name and number shown here is a
placeholder.

The facts in this guide were first worked out by the iKnow project
(github.com/8rank/iKnow), which iOwl is built on.

---

## 1. Get consent before you read anything

Anything you read from these stores lands in your context, and your context
goes to whoever runs your model. These stores describe the owner's
relationships, contacts, conversations, calendar and photos, and they also hold
scored guesses about other people, none of whom agreed to any of it. Only the
owner can decide whether your provider gets to see that.

Before your first read, tell the owner three things:

1. Which model and provider you are, as far as you actually know. If you don't
   know, say so.
2. That what you read is sent to that provider, which may log or keep it under
   terms neither of you can check.
3. What their question will make you read: names, numbers, addresses,
   relationship scores, who they talk to and when, calendar entries, and
   possibly message text.

Then ask this question and wait for the answer:

> Do you trust the provider running me with the contents of your Mac's
> knowledge graph? (yes / no)

- Ask even when the request already sounds like permission. The yes must come
  as an answer to this question.
- Until you have a yes, read nothing: no `sqlite3`, no Python against the
  stores, no iOwl endpoint, not even the access check in section 3.
- Only a plain yes counts ("yes", "go ahead", "sure"). Silence, a new question
  or "I think so" does not. Ask again or stop.
- On a no, stop. Point the owner to iOwl in the browser
  (`python3 server.py`, then the printed link), which sends nothing off the
  Mac, or to this guide with a model that runs locally.
- Ask once per session, and again if the owner switches model or provider.

---

## 2. Ground rules

1. **Never write to a store.** Open every database read-only with a `file:`
   URI and `mode=ro`:
   `sqlite3 "file:$HOME/Library/IntelligencePlatform/graph.db?mode=ro"`.
   No `INSERT`, `UPDATE`, `DELETE`, `CREATE`, `VACUUM`, `PRAGMA wal_checkpoint`
   or `PRAGMA journal_mode`. System daemons write to these files while you read.
2. **Attach read-only too.** `ATTACH 'file:/path/x.db?mode=ro' AS x`. A plain
   path in `ATTACH` opens read-write, even from a read-only connection.
3. **Do not use `immutable=1`.** It ignores the write-ahead log, which is where
   the newest facts live. If a read fails, report the failure.
4. **Copy nothing to disk.** No row values in files, commits, issues or web
   requests. Answers go to the owner in the conversation and nowhere else.
5. **Read the minimum.** Counts and filtered rows first. Ask before pulling
   whole tables of names, handles or message text.
6. **Other people are in here.** Answer what the owner asked. Don't build
   profiles of anyone else unprompted.
7. **Measure rather than repeat.** Where this guide gives a test, run it. A
   value written here is a starting point, not an answer.

---

## 3. Start with iOwl

If the owner can run iOwl, use it first. Its endpoints return counts, every
number comes with the query that produced it, and nothing personal is read to
produce them.

Ask the owner to run `python3 server.py` in the iOwl folder and give you the
token from the link it prints. It changes on every start; a `401` means the
server restarted. Then:

| Endpoint | What it returns |
|---|---|
| `/api/findings` | Every measurement, every finding with evidence and actions, what could not be measured, and the SQL behind each number |
| `/api/findings?terms=a,b` | The same, plus watchlist counts for each term |
| `/api/report?kind=brief` | The high-level brief, as HTML |
| `/api/report?kind=technical` | The technical report, as HTML |
| `/api/version` | iOwl's version |

```sh
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8765/api/findings
```

Each viewer page also has JSON at `/api/<page>` (`overview`, `identity`,
`person?id=`, `kinship`, `comms`, `calendar`, `social`, `faces`, `certainty`,
`retractions`, `device`, `exposure`). These can return names. Add `redact=1`
to swap names, numbers and addresses for numbered placeholders, especially if
the owner plans to share what you write.

### Access check

Without iOwl, or for a question it doesn't answer, confirm you can read the
graph at all. The app running your shell needs Full Disk Access (System
Settings › Privacy & Security › Full Disk Access, then quit and reopen the
app). Without it, opening fails with `unable to open database file`, which
here means "permission denied", not "file missing".

```sh
sqlite3 "file:$HOME/Library/IntelligencePlatform/graph.db?mode=ro" \
  "select count(*) from stable_graph" && echo readable
```

When the owner is finished, remind them to switch Full Disk Access off. It
covers everything run from that app.

---

## 4. Where things are

| Store | Path |
|---|---|
| The graph and its derived stores | `~/Library/IntelligencePlatform/` |
| Code book for the graph (SQLite) | `~/Library/IntelligencePlatform/ontology.db` |
| Code book (JSON) | `Resources/` inside `/System/Library/PrivateFrameworks/IntelligencePlatformCore.framework` |
| Messages | `~/Library/Messages/chat.db` |
| Calendar | `~/Library/Group Containers/group.com.apple.calendar/Calendar.sqlitedb` |
| Contacts, one per account | `~/Library/Application Support/AddressBook/Sources/<source>/AddressBook-v22.abcddb` |
| Photos | `~/Pictures/<library>.photoslibrary/database/Photos.sqlite` |

Inside `~/Library/IntelligencePlatform/` (ignore any `-fullRebuild` copies,
which are staging files):

| File | Main tables | Holds |
|---|---|---|
| `graph.db` | `stable_graph`, `event_graph`, `expired_*`, `graph_state`, `embeddings` | The graph itself: people, organizations, places, groups, apps, events, and recently withdrawn rows |
| `ontology.db` | `class`, `predicate` | What every code means |
| `Artifacts/entityTagging/entityTagging.db` | `entity_tagging` | Relationship scores per entity (section 7.5) |
| `Artifacts/siri/remembers/view.db` | `interactions`, `entities`, `interactionEntities` | The communication log: messages and calls as metadata, no text (section 7.7) |
| `Artifacts/internal/views.db` | `handle_id`, `phperson_id_map`, `entity_alias`, … | Identity maps and aliases |
| `Artifacts/entityRelevance/entityRelevanceInferences.db` | `person_entity_relevance`, … | Who matters right now, with Apple's own explanations |
| `Artifacts/entityRelevance/entityImportanceSignals.db` | `entityImportanceSignalsIDMap` | Favorite, emergency contact and iCloud Family flags |
| `Artifacts/feature/features.db` | `kv` | The inputs behind the scores and rankings |
| `views.db` | `viewConfigRecord`, `viewState` | Which derived views exist and what they read |
| `globalKnowledge.db` | `static_graph`, `live_graph` | Apple's general world knowledge, plus a cache of lookups answered off the device. Not personal. |
| `behaviors.db` | `histogram`, … | Usage histograms; how they relate to the graph is not established |

Most other stores under `Artifacts/` are copies of graph rows made for one
consumer or another.

Open stores from inside `~/Library/IntelligencePlatform` so relative `file:`
paths work (SQL does not expand `~`), and bind ids with
`.param set :id <entity id>`. In Python, set a lenient text factory, because
some columns hold bytes that are not valid UTF-8:

```python
import os, sqlite3
def open_ro(path):
    c = sqlite3.connect(f"file:{os.path.expanduser(path)}?mode=ro", uri=True)
    c.text_factory = lambda b: b.decode("utf-8", "replace")
    c.row_factory = sqlite3.Row
    return c
```

With the iOwl folder on `sys.path`, `from api import db, vocab` gives you the
same helpers iOwl uses: `db.query(store, sql)`, `vocab.owner_id()`,
`vocab.name_of(id)`, `vocab.statements(layer, subject=id)`, `vocab.plabel` and
`vocab.clabel` to decode codes, `vocab.source_names(mask)`, and
`db.apple_time(value)`.

---

## 5. How the graph is laid out

### Rows are triples

`stable_graph`, `event_graph` and their `expired_` copies share one layout:

| Column | Type | Meaning |
|---|---|---|
| `subject` | integer | The entity the row is about (64-bit id) |
| `predicate` | text | What is being said, as a code (`PS33`, `nm_bundleID`, …) |
| `relationshipId` | integer | 0 for a simple attribute; otherwise the id of the statement this row is part of |
| `relationshipPredicate` | text | Empty for a simple attribute; otherwise which part of the statement this row holds |
| `object` | text | The value, always stored as text whatever it represents |
| `sources` | integer | Bitmask of the feeds that asserted the row (section 5.4) |
| `confidence` | real | 0 to 1 |
| `sourceDuplicates` | text | The source records behind the row, separated by character 30 |
| `timestamp` | real | Apple time when the graph wrote the row |

`stable_graph` holds people, organizations, places, groups, apps and the owner.
`event_graph` holds calendar events and reservations. The `expired_` tables hold
rows the graph has recently withdrawn (section 7.10).

### Statements span several rows

A row with `relationshipId = 0` and an empty `relationshipPredicate` is a
simple attribute, such as a name. Anything richer is split across rows that
share `subject`, `predicate` and `relationshipId`, one row per part. A phone
number, for example, is a `PS520` statement made of three rows: `PS1` holding
its type (`CS97`), `PS407` holding the number and `PS740` holding the label.

So group by `relationshipId` and pivot on `relationshipPredicate`. Parts can
repeat (a group statement has one `PS566` row per member), so collect them as
lists. Counting rows counts parts, not facts.

### Ids and references

- Entity ids are signed 64-bit and often larger than 2^53. Keep them as strings
  anywhere JavaScript or floating point is involved.
- A reference to another entity is the text `md:<id>`. Follow it with
  `CAST(substr(object, 4) AS INTEGER)`. A bare number in `object` is never a
  reference.
- Recognize other namespaces by checking the start of the value against a
  known list. Never split on `:`, because ordinary text and dates contain
  colons too.

| Starts with | Points to | Can you follow it? |
|---|---|---|
| `md:` | Another entity in this graph | Yes |
| `cnContact:` | A Contacts record, `<UUID>:ABPerson` | Yes, as written (section 8.1) |
| `phPerson:` | A Photos face cluster, `<ZPERSONUUID>/L0/<nnn>` | Yes (section 8.2) |
| `ekEvent:` | A calendar event: base64 SHA-256 of `<store persistent_id>:<item unique_identifier>` | Yes, by hashing (section 8.3) |
| `lsBundleRecord:` | An installed app: base64 SHA-256 of its bundle id | Yes, by hashing |
| `sgEvent:`, `sgContact:` | Events and contacts Siri Suggestions found in mail and messages | No |
| `inPerson:` | A person from the Intents framework | No |
| `faFamilyCircle:` | A Family Sharing circle | No, but matching values mean the same circle |
| `tel:`, `mailto:`, `http:`, `https:` | Ordinary URIs | Not applicable |

The hashes are unsalted, so these references are pseudonymous, not anonymous.
Phone numbers and mail addresses also appear in plain text in `PS407` and
`PS406` parts. Dates inside `object` are JSON with fields such as `year`,
`month`, `day`, `hour`, `minute` and `timeZone.identifier`; read them with
`json_extract`. All-day entries have no `hour`. `nm_imputed*` values are Apple
time written as text.

### Where a row came from

- **`confidence`** mostly reflects which feed wrote the row, not how sure the
  system is. On the stores checked, Contacts rows were 1.0, Photos 0.9 and most
  others between 0.7 and 0.8.
- **`sources`** is a bitmask. Test each bit with `sources & (1<<n)`. Never
  `GROUP BY sources`, because many rows set several bits. This mapping was
  worked out by observation, not from Apple:

  | Bit | Feed |
  |---|---|
  | 0 | Contacts |
  | 1 | Intents (INPerson) |
  | 5 | Photos face clusters |
  | 8 | Calendar (EventKit) |
  | 10 | Siri Suggestions contacts |
  | 11 | Siri Suggestions events |
  | 13 | Family Sharing |
  | 15 | App catalog |

- **`sourceDuplicates`** names the source records behind a row, split by
  `char(30)`. It is the most direct answer to "where did this come from".
- On face links, `nm_associationReason` mixes reasons the owner gave with
  reasons a model derived. On aliases, an `nm_signalLabel` ending in
  `_provided_alias` came from a record, while `derived_alias` was generated.

### Time

Most timestamps are Apple time, seconds since 2001-01-01:
`datetime(x + 978307200, 'unixepoch', 'localtime')`. `chat.db` keeps
`message.date` in nanoseconds, so divide by 1e9 first. A `timestamp` is when
the graph wrote the row, not when the thing happened. A value of `0.0` means
"never", so filter `> 0`.

---

## 6. Codes

`SB` codes are classes, `CS` codes are statement types, `PS` codes are
predicates, and `nm_` codes are Apple's local additions. Decode any of them
from `ontology.db`:

```sql
ATTACH 'file:ontology.db?mode=ro' AS o;
SELECT g.predicate, p.label, COUNT(*) AS n
FROM stable_graph g LEFT JOIN o.predicate p ON p.id = g.predicate
GROUP BY 1 ORDER BY n DESC;
```

Classes you will see most: `SB104` person, `SB10` organization, `SB152` place,
`SB2` group of people, `SB144` software, `SB472` calendar event.

| Code | Means | Parts |
|---|---|---|
| `PS1` | Is a (class) | |
| `PS33`, `PS312`, `PS546`, `PS441` | Name, first, middle, family name | |
| `nm_isCurrentUser` | The owner (one entity) | |
| `PS102` | Same as: a reference into another store | |
| `PS520` | Contact information | `PS407` phone, `PS406` mail, `PS740` label |
| `nm_entityAliasRelationship` | An alias | `PS89` text, `nm_signalLabel`, `nm_confirmationConfidence` |
| `nm_hasVisualIdentifier` | A face | `nm_visualIdentifier` (Photos cluster), `nm_associationReason` |
| `PS500` | Employer | `PS45` the organization (`md:`), `PS548` department |
| `PS753` | Group membership | `PS566` each member (`md:`) |
| `PS317` | Postal address | `PS316` street, `PS453` city, `PS315` postal code, `PS450` country |
| `PS225` | Location | `PS107` the place (`md:`) |
| `nm_bundleID`, `PS194` | App bundle id, publisher | |
| `PS33`, `PS51` on events | Title, and the full description word for word, often written by someone else | |
| `nm_hasDate` on events | Dates | `PS29` start, `PS30` end |
| `PS232`, `PS578` on events | Attendee, organizer | `PS143` the person (`md:`) |
| `nm_virtualConferenceURL` | Join links and dial-ins | A `tel:` here is a dial-in, not a person |

Events arrive from two feeds that never share a subject, so never join them:
EventKit (bit 8) brings attendees but no descriptions, and Siri Suggestions
(bit 11) brings descriptions and reservations found in mail but no attendees.

---

## 7. Answering common questions

All of these run against `graph.db` unless noted.

### 7.1 Which entity is the owner?

```sql
SELECT subject FROM stable_graph WHERE predicate = 'nm_isCurrentUser';
```

Leave this id out of every "top people" list.

### 7.2 Find a person by name or handle

```sql
SELECT DISTINCT subject, predicate, relationshipPredicate, object
FROM stable_graph
WHERE object LIKE '%' || :name || '%'
  AND (predicate IN ('PS33', 'PS312', 'PS441', 'PS546')
       OR (predicate = 'nm_entityAliasRelationship' AND relationshipPredicate = 'PS89'));
```

To find someone by phone or mail address, search the `PS407` and `PS406` parts
of `PS520` (match phone numbers on their last nine digits), or run
`SELECT id FROM handle_id WHERE handle = :handle` in `internal/views.db`.
Many entities have no name at all. Describe them by what they do have, and
never make up a name.

### 7.3 Everything about one entity

```sql
ATTACH 'file:ontology.db?mode=ro' AS o;

-- what it says
SELECT g.predicate, p.label, g.relationshipId AS rid,
       g.relationshipPredicate AS part, f.label AS part_label,
       g.object, g.confidence, g.sources,
       datetime(g.timestamp + 978307200, 'unixepoch') AS written
FROM stable_graph g
LEFT JOIN o.predicate p ON p.id = g.predicate
LEFT JOIN o.predicate f ON f.id = g.relationshipPredicate
WHERE g.subject = :id
ORDER BY g.predicate, g.relationshipId, g.relationshipPredicate;

-- what points at it: groups, employees, events it attends
SELECT 'stable' AS layer, subject, predicate, relationshipPredicate
FROM stable_graph WHERE object = 'md:' || :id
UNION ALL
SELECT 'event', subject, predicate, relationshipPredicate
FROM event_graph WHERE object = 'md:' || :id;
```

The same id is the key in `entity_tagging`, `entityImportanceSignalsIDMap`,
`person_entity_relevance`, `handle_id` and `phperson_id_map`.

### 7.4 Contact details, employer, address

```sql
-- phone numbers and mail addresses
SELECT relationshipId,
  MAX(CASE WHEN relationshipPredicate = 'PS407' THEN object END) AS phone,
  MAX(CASE WHEN relationshipPredicate = 'PS406' THEN object END) AS mail,
  MAX(CASE WHEN relationshipPredicate = 'PS740' THEN object END) AS label
FROM stable_graph WHERE predicate = 'PS520' AND subject = :id
GROUP BY relationshipId;

-- employer and department
SELECT org.object AS organization, dep.object AS department, e.confidence
FROM stable_graph e
JOIN stable_graph org ON org.subject = CAST(substr(e.object, 4) AS INTEGER)
                     AND org.predicate = 'PS33'
LEFT JOIN stable_graph dep ON dep.subject = e.subject AND dep.relationshipId = e.relationshipId
                          AND dep.relationshipPredicate = 'PS548'
WHERE e.subject = :id AND e.predicate = 'PS500' AND e.relationshipPredicate = 'PS45';

-- postal addresses
SELECT subject, relationshipId,
  MAX(CASE WHEN relationshipPredicate = 'PS316' THEN object END) AS street,
  MAX(CASE WHEN relationshipPredicate = 'PS453' THEN object END) AS city,
  MAX(CASE WHEN relationshipPredicate = 'PS315' THEN object END) AS postal_code,
  MAX(CASE WHEN relationshipPredicate = 'PS450' THEN object END) AS country
FROM stable_graph WHERE predicate = 'PS317'
GROUP BY subject, relationshipId;
```

Remove the `_$!<…>!$_` wrapping from `PS740` labels before showing them. An
address on a person was usually copied from their contact card; check the
subject's class before saying "X lives at".

### 7.5 Relationship scores

In `Artifacts/entityTagging/entityTagging.db`. `mdid` is the entity id stored
as text.

```sql
-- inside entityTagging.db
ATTACH 'file:graph.db?mode=ro' AS g;

SELECT t.mdid,
  (SELECT object FROM g.stable_graph n WHERE n.subject = CAST(t.mdid AS INTEGER)
     AND n.predicate = 'PS33' ORDER BY n.confidence DESC, length(n.object) DESC LIMIT 1) AS name,
  (SELECT object FROM g.stable_graph k WHERE k.subject = CAST(t.mdid AS INTEGER)
     AND k.predicate = 'PS1' AND k.relationshipId = 0 LIMIT 1) AS class,
  ROUND(t.familyAndFriends, 3) AS family_and_friends, ROUND(t.family, 3) AS family
FROM entity_tagging t
ORDER BY t.familyAndFriends DESC LIMIT 40;
```

Read the score columns from `PRAGMA table_info(entity_tagging)` rather than
assuming them, because they change between releases. Things to keep in mind:

- These scores are inferred, and how they are computed is not documented.
- Most columns are sparse and take a few fixed values (0.125, 0.25, 0.5);
  `family` and `familyAndFriends` vary more.
- Scores bunch near the top and organizations can score as family, so compare
  a score with the rest of the table, not with 0.5, and look at the evidence
  (section 7.11).
- The table has no timestamp and can go on scoring entities the live graph has
  dropped. Check that the `mdid` still has rows in `stable_graph`.
- Nothing documented is known to act on these scores. Don't say they "decide"
  anything.

### 7.6 What the owner declared about family

```sql
-- inside Artifacts/entityRelevance/entityImportanceSignals.db
SELECT entityIdentifier, isFavorite, isEmergencyContact, isICloudFamily, relationshipLabel
FROM entityImportanceSignalsIDMap
WHERE isFavorite OR isEmergencyContact OR isICloudFamily OR coalesce(relationshipLabel, '') <> '';
```

Entities sharing the owner's `faFamilyCircle:` value are in their Family
Sharing circle, and a `PS753` group with bit 13 set is the Family Sharing
group. These flags, and the relations typed into Contacts (section 8.1), are
things the owner stated. The scores in 7.5 are inferred. When they disagree,
show both and say which is which.

### 7.7 Who the owner talks to

In `Artifacts/siri/remembers/view.db`. `interactions` has one row per message
or call (`domain`, `bundleId`, `direction`, `handlingStatus`, `startDate`,
`durationSeconds`, `contentHash`, `isLocal`, `remoteDeviceId`). `entities`
holds the other parties (`type` is `Person`, `PersonHandle` or `MessageGroup`;
`id` is the handle; the `fields` JSON has `name`).
`interactionEntities (interactionRowid, entityRowid, parameter)` links them,
with roles such as `sender` and `recipients`.

Work out what `direction` means on this Mac before using it. Don't assume
Apple's public enum. Only incoming rows have a `sender`, so:

```sql
SELECT i.direction, COUNT(*) AS n,
  SUM(EXISTS (SELECT 1 FROM interactionEntities ie
              WHERE ie.interactionRowid = i.rowid AND ie.parameter = 'sender')) AS has_sender
FROM interactions i GROUP BY 1;
```

Likewise, the connected-call status is the `handlingStatus` whose `Calls` rows
carry a duration. Most frequent counterparts:

```sql
ATTACH 'file:Artifacts/internal/views.db?mode=ro' AS iv;

SELECT h.id AS entity, COUNT(DISTINCT i.rowid) AS interactions,
  SUM(i.domain = 'Calls') AS calls, SUM(i.domain = 'Messages') AS messages,
  datetime(MIN(i.startDate) + 978307200, 'unixepoch', 'localtime') AS first_seen,
  datetime(MAX(i.startDate) + 978307200, 'unixepoch', 'localtime') AS last_seen
FROM entities e
JOIN iv.handle_id h ON h.handle = e.id
JOIN interactionEntities ie ON ie.entityRowid = e.rowid
JOIN interactions i ON i.rowid = ie.interactionRowid
WHERE e.type = 'PersonHandle'
GROUP BY h.id ORDER BY interactions DESC LIMIT 25;
```

When you report on this log, say that it covers a limited window (measure it)
and holds metadata only, never message text. `contentHash` identifies a
conversation, not a message. `handle_id` is many-to-many. Rows with
`isLocal = 0`, or a `remoteDeviceId`, came from another of the owner's devices,
so count them before saying "on this Mac".

### 7.8 Calendar

```sql
SELECT st.subject AS event,
  (SELECT object FROM event_graph t WHERE t.subject = st.subject AND t.predicate = 'PS33' LIMIT 1) AS title,
  printf('%04d-%02d-%02d %02d:%02d',
    json_extract(st.object, '$.year'), json_extract(st.object, '$.month'),
    json_extract(st.object, '$.day'), coalesce(json_extract(st.object, '$.hour'), 0),
    coalesce(json_extract(st.object, '$.minute'), 0)) AS starts,
  json_extract(st.object, '$.timeZone.identifier') AS tz
FROM event_graph st
WHERE st.relationshipPredicate = 'PS29'
ORDER BY starts;

-- the people the owner shares the most events with
SELECT CAST(substr(object, 4) AS INTEGER) AS person, COUNT(DISTINCT subject) AS events
FROM event_graph
WHERE predicate = 'PS232' AND relationshipPredicate = 'PS143'
  AND object <> 'md:' || (SELECT subject FROM stable_graph WHERE predicate = 'nm_isCurrentUser')
GROUP BY 1 ORDER BY events DESC LIMIT 25;
```

Each time is wall-clock time in its own `tz`. Most attendees are known only by
the address they were invited at. Quote descriptions no further than the
question needs. The graph holds part of the calendar; `Calendar.sqlitedb` holds
all of it (section 8.3).

### 7.9 Who matters right now

```sql
-- inside Artifacts/entityRelevance/entityRelevanceInferences.db
SELECT mdid, ROUND(relevanceScore, 4) AS score,
  json_extract(explanation, '$.positiveContributions') AS raised_by,
  json_extract(explanation, '$.negativeContributions') AS lowered_by
FROM person_entity_relevance ORDER BY relevanceScore DESC LIMIT 20;
```

`person_entity_longterm` is the longer-horizon version and
`loi_entity_relevance` ranks places. The inputs include time, place and Wi-Fi.
The explanation JSON is Apple's own account of each ranking: quote it, and
don't add reasons of your own.

### 7.10 Installed apps and withdrawn facts

```sql
SELECT subject, object AS bundle_id,
  datetime(timestamp + 978307200, 'unixepoch') AS first_written
FROM stable_graph WHERE predicate = 'nm_bundleID';
```

`first_written` is when the graph recorded the app, not when it was installed.

To see what became of withdrawn rows:

```sql
SELECT fate, COUNT(*) FROM (
  SELECT CASE
    WHEN EXISTS (SELECT 1 FROM stable_graph l WHERE l.subject = e.subject AND l.predicate = e.predicate
                 AND l.relationshipPredicate = e.relationshipPredicate AND l.object = e.object) THEN 'asserted again'
    WHEN EXISTS (SELECT 1 FROM stable_graph l WHERE l.subject = e.subject AND l.predicate = e.predicate) THEN 'replaced'
    WHEN EXISTS (SELECT 1 FROM stable_graph l WHERE l.subject = e.subject) THEN 'withdrawn'
    ELSE 'entity gone' END AS fate
  FROM expired_stable_graph e)
GROUP BY fate;
```

Run the same for `expired_event_graph`. Many withdrawn rows are rewrites rather
than deletions. The archive only reaches back to
`expiredTriplesPruneTimestamp` in `graph_state`, about 48 hours where measured,
so it shows recent change, not history.

### 7.11 The evidence behind a score

In `Artifacts/feature/features.db`, table
`kv (viewName, featureName, subidentifierName, value)`. Per-person rows have
`subidentifierName = 'md:<id>'`. The view `personEntityTaggingFacts` holds the
facts the scorer checked (`sameLastName`, `iCloudFamilyMember`,
`photosPersonAge`, …); `personEntityTagging` and `photosPersonEntityTagging`
hold the behavioral profile. Each `value` is an `NSKeyedArchiver` plist:

```python
import plistlib
def read_feature(blob):
    objs = plistlib.loads(blob)["$objects"]
    top = objs[1]
    get = lambda u: objs[u.data] if isinstance(u, plistlib.UID) else u
    return get(top.get("type")), get(top.get("value"))
```

A row means the question was asked, not that the answer was yes. Count the
true values.

---

## 8. Following references into the source stores

Open these read-only as well.

### 8.1 Contacts

Drop the `cnContact:` prefix and match the rest, `:ABPerson` suffix included,
against `ZABCDRECORD.ZUNIQUEID`. A few match `ZLINKID` instead. Check every
account's `AddressBook-v22.abcddb`.

```sql
SELECT Z_PK, ZFIRSTNAME, ZLASTNAME, ZORGANIZATION
FROM ZABCDRECORD WHERE ZUNIQUEID = :cn OR ZLINKID = :cn;

-- relations the owner typed, such as "mother" or "partner"
SELECT ZNAME, ZLABEL FROM ZABCDRELATEDNAME WHERE ZOWNER = :pk;
```

Show `ZABCDRELATEDNAME` beside the scores in 7.5: one is declared, the other
inferred. Phones, mail and postal addresses are in `ZABCDPHONENUMBER`,
`ZABCDEMAILADDRESS` and `ZABCDPOSTALADDRESS`, keyed by `ZOWNER`.

### 8.2 Photos

The part of `nm_visualIdentifier` before the first `/` is
`ZPERSON.ZPERSONUUID`, in plain text.

```sql
SELECT Z_PK, ZFULLNAME, ZDISPLAYNAME FROM ZPERSON WHERE ZPERSONUUID = :uuid;

SELECT a.ZUUID, datetime(a.ZDATECREATED + 978307200, 'unixepoch', 'localtime') AS taken
FROM ZDETECTEDFACE f JOIN ZASSET a ON a.Z_PK = f.ZASSETFORFACE
WHERE f.ZPERSONFORFACE = :person_pk AND a.ZTRASHEDSTATE = 0
ORDER BY a.ZDATECREATED DESC;
```

Measure a cluster by counting `ZDETECTEDFACE` rows; `ZFACECOUNT` is a cached
value that goes stale. Scene labels join through
`ZMEDIAANALYSISASSETATTRIBUTES`, not `ZASSET`. The face attribute codes have no
label table, so report how many faces carry them and nothing more. A latitude
or longitude of `-180.0` means no location.

### 8.3 Calendar

SQLite has no SHA-256, so build the `ekEvent:` lookup in Python and keep the
`=` padding:

```python
import base64, hashlib
rows = cal.execute("""
  SELECT ci.ROWID, s.persistent_id || ':' || ci.unique_identifier
  FROM CalendarItem ci
  JOIN Calendar c ON c.ROWID = ci.calendar_id
  JOIN Store s ON s.ROWID = c.store_id
  WHERE ci.unique_identifier IS NOT NULL AND s.persistent_id IS NOT NULL""")
by_token = {"ekEvent:" + base64.b64encode(hashlib.sha256(p.encode()).digest()).decode(): rowid
            for rowid, p in rows}
```

`CalendarItem` has `summary`, `description`, `start_date`, `end_date` and
`location_id`; `Participant` has `email`, `role` and `status`. `sgEvent:`
values have no known source on the device.

### 8.4 Messages

No graph row points at an individual message. Join by handle, which reaches a
whole conversation.

```sql
-- inside chat.db
SELECT h.ROWID, h.id, h.service FROM handle h WHERE lower(h.id) = lower(:handle);

SELECT datetime(m.date / 1e9 + 978307200, 'unixepoch', 'localtime') AS at,
       m.is_from_me, m.text, length(m.attributedBody) AS rich_bytes
FROM message m WHERE m.handle_id = :handle_rowid
ORDER BY m.date DESC LIMIT 50;
```

On current macOS the text is often only in `attributedBody`, as a UTF-8 run
after the `NSString` marker. `chat.db` covers Messages only; other messengers
appear only as metadata in the log (7.7). This is the most sensitive join in
this guide. Read message text only when the owner asks for it.

---

## 9. Mistakes that give wrong answers without an error

1. A plain `ATTACH` opens read-write; `immutable=1` hides the newest facts.
2. Finding a namespace by splitting on `:` (section 5.3).
3. Counting rows when you mean statements (section 5.2).
4. `GROUP BY sources`, or splitting `sourceDuplicates` on commas (section 5.4).
5. Casting a date value to a number. It is JSON, and every event lands on
   2001-01-01.
6. Reading `timestamp` as when something happened, or `0.0` as a date.
7. Passing entity ids through JavaScript or a float.
8. Joining `mdid` (text) without `CAST(mdid AS INTEGER)`.
9. Stripping `:ABPerson` from Contacts ids, or `=` padding from tokens.
10. Trusting `direction` or `handlingStatus` to follow Apple's public enums, or
    treating `contentHash` as a message id.
11. Taking an event-layer `tel:` for a person's number, or joining EventKit
    events to Siri Suggestions events.
12. Using `ZFACECOUNT`, or joining scene labels to `ZASSET`.
13. Leaving the owner in a ranking of their contacts.
14. Reading a `-fullRebuild` staging copy.
15. Taking any `PS33`. Some entities have two; prefer higher confidence, then
    the longer value.
16. Hard-coding score columns. Read them from `PRAGMA table_info`.
17. Treating two live stores read a second apart as one snapshot.

---

## 10. What is known about the system, and what isn't

- **Who builds it.** `knowledgeconstructiond`, working with
  `intelligenceplatformd` (both have man pages), roughly daily while on power,
  one source at a time.
- **What it is for.** Mostly entity resolution and relevance: working out which
  person, place or app a request refers to. Apple describes the design in
  *Growing and Serving Large Open-domain Knowledge Graphs* (SIGMOD 2023,
  arXiv 2305.09464).
- **Who reads it.** Programs holding private
  `com.apple.private.intelligenceplatform.*` entitlements, each listing the
  views it may read (`codesign -d --entitlements - <path>`). Siri inference
  (`siriinferenced`) has the longest list, and the Apple Intelligence runtime
  (`generativeexperiencesd`) can read the graph layers. No third-party program
  was found with these entitlements, but apps in `/Applications` were not
  checked. `viewConfigRecord` in `views.db` lists the views.
- **Whether it leaves the Mac.** No evidence was found that graph content syncs
  or uploads. That is an open question, not a clean result. `globalKnowledge.db`
  caches answers fetched from off the device. Whether backups include the graph
  is not settled.
- **Encryption.** None found beyond macOS privacy controls and FileVault.
- **Deletion.** Removing a contact, event or photo removes what was derived from
  it on a later run, though the scores can lag (7.5). There is no control for
  the owner to view or clear the graph.

Not covered, or not understood: message and mail bodies are not in the graph
(message text is only in `chat.db`, though events found in mail do arrive as
`sgEvent` entities); there is no history beyond the short withdrawal window;
the histogram blobs in `behaviors.db` and `internal/views.db`,
`communicationMechanism` codes, what the `*ContextEvents` identifiers mean,
source bits beyond section 5.4, the scorer's internal thresholds and the
`embeddings` table are not decoded. Say so rather than guessing.

---

## 11. Reporting back

- Name the layer each answer comes from: a contact card (copied, bit 0), the
  scores (inferred) or the communication log (metadata).
- Give scale: the denominator, where a score sits in its table, and whether a
  list was cut short.
- Write "the store says", not "Apple thinks".
- Report absences as findings: "no face cluster is linked to this person".
- Name unresolved entities by what they have: a handle, an address, "an
  unnamed person at 4 of your events".
- Keep it plain. Numbers beat adjectives.
- If iOwl is running, point the owner to the matching page or report. Its
  `api/` modules show how each trap above is handled in practice.
