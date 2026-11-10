"""test_iowl.py — iOwl against a made-up Mac with known answers.

    python3 -m unittest discover -s tests -v

Three things are checked:

  1. Every count the findings engine reports matches what tests/make_fixture.py
     put there, worked out by hand.
  2. Neither report contains any name, phone number, address, group name or
     event title from the fixture. This is the redaction guarantee, tested.
  3. The server still refuses a request without its token, and serves the
     reports with the strict Content-Security-Policy when given one.

Standard library only, like the rest of iOwl.
"""

import html.parser
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import make_fixture  # noqa: E402
from api import db, findings, report  # noqa: E402

TERMS = "example.org, Acme Mission"


def v(m):
    return m["value"] if isinstance(m, dict) else m


class _Tags(html.parser.HTMLParser):
    VOID = {"meta", "link", "img", "br", "hr", "input"}

    def __init__(self):
        super().__init__()
        self.stack, self.errors, self.ids, self.hrefs = [], [], set(), []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if "id" in a:
            self.ids.add(a["id"])
        if tag == "a" and a.get("href", "").startswith("#"):
            self.hrefs.append(a["href"][1:])
        if tag not in self.VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if tag in self.VOID:
            return
        if not self.stack or self.stack[-1] != tag:
            self.errors.append(f"unexpected </{tag}> with open {self.stack[-3:]}")
            if tag in self.stack:
                while self.stack and self.stack.pop() != tag:
                    pass
        else:
            self.stack.pop()


class FindingsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="iowl-fixture-")
        make_fixture.build(cls.tmp)
        db.configure(bundle=cls.tmp)
        db.begin()
        cls.data = findings.collect({"terms": TERMS})
        cls.gaps = db.gaps()
        db.close()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_profile_counts(self):
        p, X = self.data["profile"], make_fixture.EXPECTED
        for key in ("people", "people_contacts", "people_outside_contacts", "people_photos",
                    "people_unnamed", "people_faces", "people_reachable", "people_employer",
                    "people_address", "orgs", "places", "events", "events_described",
                    "event_attendees", "expired", "embeddings", "embedding_types"):
            self.assertEqual(v(p[key]), X[key], key)
        self.assertEqual(p["archive_hours"], X["archive_hours"])

    def test_comms_counts(self):
        c, X = self.data["comms"], make_fixture.EXPECTED
        self.assertEqual(v(c["total"]), X["log_total"])
        pm, wk = c["by_kind"]["private_messenger"], c["by_kind"]["work_collab"]
        self.assertEqual(pm["entries"], X["pm_entries"])
        self.assertEqual(pm["handles"], X["pm_handles"], "distinct across apps, not a sum")
        self.assertEqual(pm["groups"], X["pm_groups"])
        self.assertEqual(wk["entries"], X["work_entries"])
        self.assertEqual(wk["groups"], X["work_groups"])
        self.assertEqual(v(c["remote"]), X["remote"])
        self.assertEqual(v(c["remote_devices"]), X["remote_devices"])

    def test_scorecard_counts(self):
        s, X = self.data["scorecard"], make_fixture.EXPECTED
        self.assertEqual(v(s["scored"]), X["scored"])
        self.assertEqual(v(s["with_role"]), X["with_role"])
        self.assertEqual(v(s["orgs_scored"]), X["orgs_scored"])

    def test_apps(self):
        a, X = self.data["apps"], make_fixture.EXPECTED
        self.assertEqual(v(a["count"]), X["apps"])
        self.assertEqual(sorted({s["product"] for s in a["security"]}), X["security_products"])

    def test_watchlist(self):
        rows = {r["term"].lower(): r for r in self.data["watchlist"]["rows"]}
        for term, want in make_fixture.EXPECTED["watch"].items():
            for key, n in want.items():
                self.assertEqual(rows[term][key], n, f"{term} / {key}")

    def test_expected_findings_fire(self):
        ids = {f["id"]: f["severity"] for f in self.data["findings"]}
        for fid, sev in (("F-01", "medium"), ("F-02", "medium"), ("F-03", "low"), ("F-04", "low"),
                         ("F-05", "info"), ("F-06", "medium"), ("F-07", "high"), ("F-08", "medium"),
                         ("F-09", "high"), ("F-10", "medium"), ("F-13", "medium"), ("F-14", "info")):
            self.assertEqual(ids.get(fid), sev, fid)

    def test_not_measured_is_listed(self):
        areas = {u["area"] for u in self.data["unmeasured"]}
        self.assertIn("FileVault and Full Disk Access", areas, "an extracted copy says nothing about protections")

    def test_every_evidence_ref_resolves(self):
        known = {q["id"] for q in self.data["queries"]} | {None}
        for f in self.data["findings"]:
            for ev in f["evidence"]:
                for part in re.split(r"[+,]", ev.get("ref") or ""):
                    self.assertIn(part or None, known, f"{f['id']} cites {part}")

    def test_no_store_gaps(self):
        self.assertEqual([g for g in self.gaps if g["kind"] != "redact"], [])


class ReportTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="iowl-fixture-")
        make_fixture.build(cls.tmp)
        db.configure(bundle=cls.tmp)
        cls.pages = {}
        for kind in ("brief", "technical"):
            db.begin()
            status, ctype, body = report.handler({"kind": kind, "terms": TERMS})
            db.close()
            cls.pages[kind] = (status, ctype, body.decode("utf-8"))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_status_and_type(self):
        for kind, (status, ctype, _body) in self.pages.items():
            self.assertEqual(status, 200, kind)
            self.assertTrue(ctype.startswith("text/html"), kind)

    def test_no_secret_reaches_a_report(self):
        for kind, (_s, _c, body) in self.pages.items():
            for secret in make_fixture.SECRETS:
                self.assertNotIn(secret, body, f"{kind} report leaks {secret!r}")

    def test_markup_is_balanced_and_links_resolve(self):
        for kind, (_s, _c, body) in self.pages.items():
            p = _Tags()
            p.feed(body)
            self.assertEqual(p.errors, [], kind)
            missing = [h for h in p.hrefs if h not in p.ids]
            self.assertEqual(missing, [], f"{kind}: anchors with no target")

    def test_no_inline_script_or_style(self):
        for kind, (_s, _c, body) in self.pages.items():
            self.assertNotIn("<style", body, kind)
            self.assertIsNone(re.search(r"<script(?![^>]*\bsrc=)", body), kind)
            self.assertIsNone(re.search(r"\son[a-z]+=", body), kind)

    def test_brief_carries_its_limits(self):
        body = self.pages["brief"][2]
        self.assertIn("What this brief cannot tell you", body)
        self.assertIn("not measured", body)
        self.assertIn("leaves the Mac", body)

    def test_technical_has_every_query(self):
        body = self.pages["technical"][2]
        self.assertIn("Appendix A. Queries", body)
        self.assertIn('id="Q1"', body)


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class ServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="iowl-fixture-")
        make_fixture.build(cls.tmp)
        cls.port = _free_port()
        cls.proc = subprocess.Popen(
            [sys.executable, os.path.join(ROOT, "server.py"), "--port", str(cls.port), "--bundle", cls.tmp],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        cls.token = None
        deadline = time.time() + 20
        while time.time() < deadline and cls.token is None:
            line = cls.proc.stdout.readline()
            m = re.search(r"\?token=(\S+)", line or "")
            if m:
                cls.token = m.group(1)
        if cls.token is None:
            cls.proc.kill()
            raise RuntimeError("server did not print a link")

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        try:
            cls.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            cls.proc.kill()
        cls.proc.stdout.close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def get(self, path, token=True):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}",
                                     headers={"Host": f"127.0.0.1:{self.port}"})
        if token:
            req.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(req, timeout=30) as res:
                return res.status, dict(res.headers), res.read()
        except urllib.error.HTTPError as err:
            return err.code, dict(err.headers), err.read()

    def test_refuses_without_token(self):
        for path in ("/api/report?kind=brief", "/api/findings", "/"):
            status, _h, _b = self.get(path, token=False)
            self.assertEqual(status, 401, path)

    def test_serves_reports_with_strict_csp(self):
        for kind in ("brief", "technical"):
            status, headers, body = self.get(f"/api/report?kind={kind}&terms=example.org")
            self.assertEqual(status, 200, kind)
            csp = headers.get("Content-Security-Policy", "")
            self.assertIn("script-src 'self'", csp)
            self.assertIn("connect-src 'self'", csp)
            self.assertIn(b"iOwl", body)

    def test_report_assets_are_served(self):
        for path in ("/css/report.css", "/js/report.js", "/logo.svg", "/js/pages/reports.js"):
            status, _h, _b = self.get(path)
            self.assertEqual(status, 200, path)

    def test_findings_json(self):
        status, _h, body = self.get("/api/findings?terms=example.org")
        self.assertEqual(status, 200)
        self.assertIn(b'"F-07"', body)


if __name__ == "__main__":
    unittest.main()
