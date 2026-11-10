<p align="center">
  <img src="public/logo.svg" width="88" alt="">
</p>

<h1 align="center">iOwl</h1>

<p align="center">See what your Mac knows about you, and report it.</p>

macOS builds a knowledge graph about the person who uses it: who they know, how
it decided those people are related to them, who they write to and how often,
whose faces recur in their photos. Apple documents very little of it and gives
no way to look at it.

iOwl is built on [iKnow](https://github.com/8rank/iKnow) by the Eighth Rank,
which opens that graph on your own Mac and shows you what is in it. iOwl keeps
everything iKnow does and adds what a security team needs next: findings, and
two reports you can hand to someone else.

## What iOwl adds

- **A findings engine.** A fixed set of measurements and rules that turn the
  store into findings, each with its evidence, its impact and what to do about
  it. Severity is stated as a word (High, Medium, Low, Note), never by colour
  alone.
- **Two reports from the same measurements.**
  - *High-level brief*: a few pages in plain language for leadership and staff.
    What the Mac holds, why it matters, what to do, and what the brief cannot
    tell you.
  - *Technical report*: scope and store hashes, every finding with its
    evidence, the communication log by app, the security software the store
    names, the watchlist, and an appendix giving the exact SQL behind every
    number.
- **Counts only, by construction.** No query behind a report returns a name,
  phone number, address or message. App identifiers read from the stores pass
  through redaction before they are shown, and if redaction cannot run they are
  withheld. The tests check that no name, number or address from a test Mac
  reaches either report.
- **An organization watchlist.** Mail domains, the organization's name, team
  names: the reports count where each appears, never what it matched. Message
  text is never searched.
- **Protection checks.** When run live on a Mac, FileVault status and the apps
  holding Full Disk Access, each of which can read the whole store.
- **Not measured is not zero.** A store that cannot be read is listed as not
  measured, with the reason. Both reports also list the open questions iOwl
  cannot answer from one Mac, so a short list of findings is never read as an
  all-clear.

## Run it

```sh
cd iowl
python3 server.py
```

Open the link it prints, then choose **Reports** in the sidebar. Each report
opens in its own tab with a **Print or save as PDF** button.

iOwl needs only Python 3.9 or later, which macOS includes. No packages, no build
step.

### Full Disk Access

The stores are protected by macOS privacy controls, so the app you start the
server from (Terminal, iTerm, your editor) needs **Full Disk Access**:
System Settings › Privacy & Security › Full Disk Access. Add it, quit the app
fully and reopen it. When you are done, switch it off again: the permission
covers everything you run from that app, not only iOwl.

### The watchlist

Copy `watchlist.example.txt` to `watchlist.txt` and put one term per line, or
type terms on the Reports page (those are not saved). `watchlist.txt` is in
`.gitignore`, because a watchlist names your organization.

### Reading a copy instead of this Mac

```sh
python3 server.py --bundle /path/to/extracted    # graph/, ontology/, sources/
```

On an extracted copy, FileVault and Full Disk Access are reported as not
measured: a copy says nothing about the machine it came from.

## Asking an AI agent

`MANUAL_FOR_YOUR_AGENT.md` is a guide for an AI agent with a shell on your Mac.
It makes the agent ask whether you trust its provider before it reads
anything, points it at iOwl's counts-only endpoints first, and covers the raw
stores for questions iOwl doesn't answer. Unlike iOwl in the browser, an agent
sends what it reads to wherever its model runs.

## The rules stay readable

- `api/findings.py` holds every measurement and every rule.
- `api/catalog.py` is the list of bundle-id prefixes that decide which apps
  count as private messengers, work tools, endpoint security, device
  management, VPNs, password managers and remote access. The technical report
  prints the whole list. Add to it freely.
- `api/report.py` renders both reports from the same data.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

`tests/make_fixture.py` builds a small, entirely made-up Mac with known
answers. The tests check every count against it, check that nothing personal
from it reaches either report, check the report markup, and start the server to
confirm it still refuses requests without its token.

## How it stays local

Unchanged from iKnow: one Python process, standard library only, bound to
127.0.0.1, a fresh token at each start, every database opened read-only, and
nothing written to disk. The reports are served the same way, under the same
Content-Security-Policy, and printed by your browser.

## Limits

- Apple changes these stores between macOS releases. iKnow was tested on macOS
  26.6.2, 26.7.1 and 27.0.1; iOwl adds no store access beyond what iKnow reads,
  plus the privacy database for the Full Disk Access check.
- The severity of a finding is a judgment, stated so it can be argued with.
- Settings that might stop new entries in the communication log are reported
  as candidates, not fixes, until they have been tested on a real device.
- iKnow is LLM-generated, and iOwl extends it. Check a finding against its
  source before you rely on it.

## License

Apache 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
