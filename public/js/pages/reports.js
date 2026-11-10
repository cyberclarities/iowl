/* reports.js — the two iOwl reports, and the findings they are built from.
 *
 * Everything shown here comes from /api/findings. The reports themselves are
 * separate printable pages (/api/report?kind=brief|technical) built from the
 * same call, so what this page lists and what the reports say cannot drift.
 *
 * Watchlist terms typed here travel with the request and are not stored
 * anywhere. Terms that should persist go in watchlist.txt beside server.py.
 */

import { api } from '../app.js';
import { h, statTile } from '../viz.js';

export const meta = {
  id: 'reports',
  nav: 'Reports',
  group: 'Start here',
  kicker: 'Reports',
  title: 'Two reports from one set of measurements',
  blurb: 'A high-level brief for leadership and staff, and a technical report for the security team. '
       + 'Both are counts only: no name, number, address or message is read to produce them. '
       + 'Every number in the technical report links to the query that produced it.',
};

const LABEL = { high: 'High', medium: 'Medium', low: 'Low', info: 'Note' };
const TONE = { high: 'critical', medium: 'serious', low: 'warning', info: '' };

let terms = '';

function reportUrl(kind) {
  const qs = new URLSearchParams({ kind });
  if (terms.trim()) qs.set('terms', terms.trim());
  return `/api/report?${qs.toString()}`;
}

function sevPill(sev) {
  return h('span', { class: `sev-pill sev-${sev}`, text: LABEL[sev] });
}

function openCard() {
  const link = (kind, title, what) => h('a', {
    class: 'report-link', href: reportUrl(kind), target: '_blank', rel: 'noopener',
  }, [h('strong', { text: title }), h('span', { text: what })]);
  return h('section', { class: 'card card-wide' }, [
    h('header', { class: 'card-head' }, [h('h3', { text: 'Open a report' })]),
    h('p', { class: 'card-note', text: 'Each opens in a new tab with a Print button. Printing to PDF gives you a file to send.' }),
    h('div', { class: 'report-links' }, [
      link('brief', 'High-level brief',
           'Two pages in plain language: what the Mac holds, why it matters, what to do, and what the brief cannot tell you.'),
      link('technical', 'Technical report',
           'Scope and store hashes, every finding with its evidence, the communication log by app, the security stack, '
           + 'the watchlist, and an appendix of every query.'),
    ]),
  ]);
}

function watchCard(rerender) {
  const box = h('textarea', {
    class: 'watch-input', rows: '2', spellcheck: 'false',
    placeholder: 'example.org, team name, product name',
    'aria-label': 'Watchlist terms, separated by commas',
  });
  box.value = terms;
  const run = h('button', { class: 'ghost', type: 'button', text: 'Measure again',
                            onclick: () => { terms = box.value; rerender(); } });
  return h('section', { class: 'card card-wide' }, [
    h('header', { class: 'card-head' }, [h('h3', { text: 'Organization watchlist' })]),
    h('p', { class: 'card-note', text:
      'Terms to look for: mail domains, the organization’s name, team or product names. The reports give how many '
      + 'times each appears in the graph, the interaction log, Calendar and Contacts. They never show the matching values, '
      + 'and message text is never searched. Terms typed here are not saved; to keep them, put one per line in '
      + 'watchlist.txt beside server.py.' }),
    h('div', { class: 'watch-row' }, [box, run]),
  ]);
}

function findingsCard(d) {
  const list = h('div', { class: 'finding-list' });
  for (const f of d.findings) {
    list.appendChild(h('div', { class: 'finding-row' }, [
      h('div', { class: 'finding-title' }, [sevPill(f.severity), h('span', { text: ` ${f.id} · ${f.title}` })]),
      h('p', { text: f.brief }),
    ]));
  }
  return h('section', { class: 'card card-wide' }, [
    h('header', { class: 'card-head' }, [h('h3', { text: 'What the reports will say' })]),
    list,
  ]);
}

function limitsCard(d) {
  const items = [
    ...d.unmeasured.map(u => h('li', {}, [h('strong', { text: u.area }), h('span', { text: `: not measured, because ${u.reason}.` })])),
    ...d.open_questions.map(q => h('li', { text: q })),
  ];
  return h('section', { class: 'card card-wide' }, [
    h('header', { class: 'card-head' }, [h('h3', { text: 'What the reports cannot tell you' })]),
    h('p', { class: 'card-note', text: 'Both reports carry this list, so an absence of findings is never read as an all-clear.' }),
    h('ul', { class: 'limits' }, items),
  ]);
}

export async function render(root) {
  const draw = async () => {
    const d = await api('findings', terms.trim() ? { terms: terms.trim() } : {});
    const c = d.severity_counts;
    root.replaceChildren(
      h('div', { class: 'grid grid-tight' }, ['high', 'medium', 'low', 'info'].map(s => statTile({
        label: s === 'info' ? 'Notes' : `${LABEL[s]} findings`, value: c[s], tone: TONE[s] || undefined,
      }))),
      openCard(),
      watchCard(() => { root.replaceChildren(h('div', { class: 'loading', text: 'measuring…' })); draw(); }),
      findingsCard(d),
      limitsCard(d),
    );
  };
  await draw();
}
