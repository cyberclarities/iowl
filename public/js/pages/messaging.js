/* messaging.js — one card per messenger: Signal, WhatsApp, Messages and the rest.
 *
 * Every count, name and date on this page arrives from /api/messaging at request
 * time. The page holds the app list's order and its own wording, nothing else.
 * People and group chat names are shown as stored; the share-safe switch swaps
 * both for numbered stand-ins before they leave the server.
 */

import { api } from '../app.js';
import { h, figure, statTile, bars, hero, keyList, tableView, compact, full } from '../viz.js';

export const meta = {
  id: 'messaging',
  nav: "Messaging apps",
  group: "What the Mac kept",
  kicker: "Signal, WhatsApp, iMessage and the rest",
  title: "What this Mac kept about each messaging app: who, how often, which way, and in which group chats",
  blurb: "No message text is read here. Siri's interaction history, its contact-and-app pairings and the installed-app list are enough to show which messengers you use, with whom, and whether anything private reached these stores. Messages' own database splits iMessage from SMS and RCS.",
};

const TONE = { 'logged': 'serious', 'present, nothing logged': 'warning' };

const n = v => (v === null || v === undefined ? '—' : full(v));

function tiles(a) {
  const box = h('div', { class: 'grid grid-tight' });
  const add = (label, value, sub) => box.appendChild(statTile({ label, value: n(value), sub }));
  add('Interactions', a.interactions, `${n(a.messages)} messages · ${n(a.calls)} calls`);
  add('Outgoing', a.sent, a.requests ? `${n(a.requests)} with no direction` : 'you sent or placed');
  add('Incoming', a.received, 'you received');
  add('People or handles', a.people, `${n(a.named)} resolve to a person`);
  add('Group chats', a.group_chats, a.group_chats ? `${n(a.in_groups)} rows in groups` : 'none tagged');
  add('Pairings', a.pairings, a.pairings ? `used ${n(a.pairing_events)} times` : 'contact-and-app');
  return box;
}

function services(s) {
  if (!s) {
    return h('p', { class: 'muted', text: "Messages' own database is not in this bundle, so the iMessage, SMS and RCS split cannot be measured." });
  }
  return h('div', {}, [
    h('h4', { text: 'By service, from Messages’ own database' }),
    tableView(['Service', 'Messages', 'Sent', 'Received', 'Chats', 'Group chats', 'Handles', 'First', 'Last'],
      s.services.map(x => [x.service, n(x.messages), n(x.sent), n(x.received), n(x.chats),
                           n(x.group_chats), n(x.handles), x.first, x.last])),
  ]);
}

function people(a) {
  if (!a.top_people.length) return null;
  const capped = a.people_total > a.people_listed
    ? ` (top ${a.people_listed} of ${full(a.people_total)})` : '';
  const box = h('details', { class: 'msg-more' });
  box.appendChild(h('summary', { text: `People and handles${capped}` }));
  box.appendChild(tableView(['Who', 'In the graph', 'Outgoing', 'Incoming', 'No direction', 'Last'],
    a.top_people.map(p => [p.name, p.resolved ? 'yes' : 'handle only', n(p.sent), n(p.received), n(p.other), p.last])));
  return box;
}

function groups(a) {
  if (!a.groups.length) return null;
  const capped = a.groups_total > a.groups.length ? ` (top ${a.groups.length} of ${full(a.groups_total)})` : '';
  const box = h('details', { class: 'msg-more' });
  box.appendChild(h('summary', { text: `Group chats${capped}` }));
  box.appendChild(tableView(['Group chat', 'Interactions', 'Last'], a.groups.map(g => [g.name, n(g.count), g.last])));
  return box;
}

function card(a) {
  const c = h('section', { class: 'card card-wide' });
  const head = h('header', { class: 'card-head' }, [
    h('h3', { text: a.product }),
    h('span', { class: 'pill' + (TONE[a.status] ? ' pill-' + TONE[a.status] : ''), text: a.status }),
  ]);
  c.appendChild(head);
  c.appendChild(h('p', { class: 'muted', text: a.kind + (a.installed ? ' · installed on this Mac' : '') }));
  if (a.interactions || a.pairings) c.appendChild(tiles(a));
  for (const line of a.story) c.appendChild(h('p', { text: line }));
  if (a.note) c.appendChild(h('p', { class: 'muted', text: a.note }));
  if (a.key === 'messages') c.appendChild(services(a.services));
  for (const extra of [people(a), groups(a)]) if (extra) c.appendChild(extra);
  if (a.bundles.length) c.appendChild(h('p', { class: 'mono muted', text: a.bundles.join(' · ') }));
  return c;
}

export async function render(root) {
  const d = await api('messaging');

  if (!d.present) {
    root.appendChild(h('div', { class: 'empty' }, [
      h('p', { text: "Neither Siri's interaction history nor Messages' database is in this bundle, so nothing on this page can be computed." }),
    ]));
    return;
  }

  const logged = d.apps.filter(a => a.interactions);
  const total = logged.reduce((s, a) => s + a.interactions, 0);

  root.appendChild(hero({
    value: total,
    label: 'messaging and calling interactions in Siri’s history, across ' + compact(logged.length) + ' apps',
    detail: d.headline,
  }));

  if (logged.length) {
    const data = logged.map(a => ({ label: a.product, value: a.interactions, meta: 'interactions' }));
    root.appendChild(h('div', { class: 'grid' }, [figure({
      title: 'Which apps reached the stores',
      note: 'One bar per app with at least one interaction. Apps with nothing logged are listed below with what is known about them.',
      chart: bars(data, { labelW: 220 }),
      table: tableView(['App', 'Interactions', 'Outgoing', 'Incoming', 'Group chats', 'People'],
        logged.map(a => [a.product, n(a.interactions), n(a.sent), n(a.received), n(a.group_chats), n(a.people)])),
      wide: true,
    })]));
  }

  const watched = d.apps.filter(a => a.watch);
  const others = d.apps.filter(a => !a.watch);
  root.appendChild(h('h2', { class: 'section-title', text: 'The messengers people ask about first' }));
  root.appendChild(h('div', { class: 'grid' }, watched.map(card)));
  if (others.length) {
    root.appendChild(h('h2', { class: 'section-title', text: 'Other messaging and calling apps that left a trace' }));
    root.appendChild(h('div', { class: 'grid' }, others.map(card)));
  }

  root.appendChild(h('div', { class: 'grid' }, [figure({
    title: 'How to read this page',
    wide: true,
    chart: keyList([
      ['Outgoing / incoming', 'Read per row from who is listed on it. A row naming a sender was received; a row naming only recipients was sent. Calls name the other party differently, so for those the direction column decides, measured by the same test the Contact log page uses.'],
      ['No trace', d.nothing],
      ['Pairings', 'Siri’s resolver keeps which app you use for which contact, so it can pick the right one when you ask it to message someone.'],
      ['Other devices', 'Most of this history is synced from your phone and other devices, not typed on this Mac.'],
      ['Not here', 'Message text, attachments and call audio. None of these stores hold them; Messages’ own database does, and this page reads only its counts.'],
    ]),
  })]));
}
