'use strict';
const $ = (id) => document.getElementById(id);
const state = {user: null, csrf: '', permits: [], filter: 'all', selected: null};
let noticeTimer;
function node(tag, text, cls) { const n = document.createElement(tag); if (text !== undefined) n.textContent = text; if (cls) n.className = cls; return n; }
function notice(message, error = false) { $('notice').textContent = message; $('notice').className = error ? 'notice error' : 'notice'; $('notice').hidden = false; clearTimeout(noticeTimer); noticeTimer = setTimeout(() => { $('notice').hidden = true; }, 6500); }
async function api(path, method = 'GET', data) {
  const options = {method, credentials: 'same-origin', headers: {}};
  if (method !== 'GET') { options.headers['Content-Type'] = 'application/json'; if (state.csrf) options.headers['X-CSRF-Token'] = state.csrf; options.body = JSON.stringify(data); }
  const response = await fetch(path, options); const body = await response.json();
  if (!response.ok) { if (response.status === 401 && path !== '/api/login') showLogin(); throw new Error(body.error || 'Request failed'); }
  return body;
}
function showLogin() { state.user = null; state.csrf = ''; state.permits = []; state.selected = null; $('login-view').hidden = false; $('workspace').hidden = true; $('identity').hidden = true; $('create-overlay').hidden = true; $('permit-list').replaceChildren(); $('detail').replaceChildren(); $('audit-list').replaceChildren(); }
async function session() {
  const result = await api('/api/session'); state.user = result.user; state.csrf = result.csrf;
  $('login-view').hidden = true; $('workspace').hidden = false; $('identity').hidden = false;
  $('who').textContent = result.user.name; $('tenant').textContent = result.user.tenant.replaceAll('-', ' ').toUpperCase() + ' / ' + result.user.role.toUpperCase();
  $('audit-panel').hidden = result.user.role !== 'reviewer'; await loadPermits();
}
async function loadPermits() { const result = await api('/api/permits'); state.permits = result.permits; if (!state.permits.some(p => p.id === state.selected)) state.selected = state.permits[0]?.id; render(); if (state.user.role === 'reviewer') await loadAudit(); }
function render() {
  for (const key of ['pending', 'approved', 'rejected']) $(key + '-count').textContent = state.permits.filter(p => p.status === key).length;
  $('record-count').textContent = state.permits.length + ' VISIBLE RECORDS';
  const search = $('search').value.toLowerCase();
  const filtered = state.permits.filter(p => (state.filter === 'all' || p.status === state.filter) && (p.species + ' ' + p.location).toLowerCase().includes(search));
  $('permit-list').replaceChildren();
  if (!filtered.length) $('permit-list').append(node('p', 'No proposals match this view.', 'help'));
  for (const permit of filtered) {
    const button = node('button', undefined, 'permit-row' + (permit.id === state.selected ? ' active' : '')); button.type = 'button'; button.setAttribute('aria-pressed', permit.id === state.selected ? 'true' : 'false');
    const top = node('span', undefined, 'row-top'); top.append(node('span', 'FIELD / ' + permit.id, 'record-id'), node('span', permit.status, 'badge ' + permit.status));
    button.append(top, node('h3', permit.species), node('p', permit.location)); button.addEventListener('click', () => { state.selected = permit.id; render(); }); $('permit-list').append(button);
  }
  renderDetail();
}
function renderDetail() {
  const detail = $('detail'); detail.replaceChildren(); const permit = state.permits.find(p => p.id === state.selected);
  if (!permit) { detail.append(node('span', 'A CLOSER LOOK', 'eyebrow'), node('h2', 'No proposals yet'), node('p', 'Start with a thoughtful fieldwork proposal.', 'muted')); return; }
  detail.append(node('span', 'FIELD NOTE / ' + permit.id, 'eyebrow'), node('h2', permit.species), node('span', permit.status, 'badge ' + permit.status));
  const list = node('dl'); for (const [label, value] of [['LOCATION', permit.location], ['SUBMITTED', permit.submitted.slice(0, 10)], ['RECORD VERSION', String(permit.version)]]) list.append(node('dt', label), node('dd', value)); detail.append(list, node('p', permit.purpose, 'purpose'));
  if (permit.review_note) { const decision = node('div', undefined, 'decision'); decision.append(node('h3', 'The review note'), node('p', permit.review_note)); detail.append(decision); }
  if (permit.status !== 'pending') return;
  if (permit.owner_id === state.user.id) { detail.append(node('p', 'Your proposal is waiting for an independent reviewer.', 'help')); return; }
  if (state.user.role !== 'reviewer') return;
  const form = node('form', undefined, 'decision'); const label = node('label', 'Explain the decision'); label.htmlFor = 'review-note';
  const note = node('textarea'); note.id = 'review-note'; note.required = true; note.minLength = 10; note.maxLength = 500; note.rows = 3;
  const approve = node('button', 'Approve fieldwork ↗', 'primary'); approve.type = 'submit'; approve.value = 'approved';
  const reject = node('button', 'Request an alternative', 'primary reject-button'); reject.type = 'submit'; reject.value = 'rejected';
  form.append(node('h3', 'Consider the impact'), label, note, approve, reject);
  form.addEventListener('submit', async (event) => { event.preventDefault(); const decision = event.submitter?.value || 'approved'; approve.disabled = true; reject.disabled = true; try { await api('/api/permits/' + permit.id + '/review', 'POST', {decision, note: note.value}); await loadPermits(); notice('Decision recorded.'); } catch (error) { notice(error.message, true); approve.disabled = false; reject.disabled = false; } }); detail.append(form);
}
async function loadAudit() { const result = await api('/api/audit'); $('audit-list').replaceChildren(); if (!result.events.length) $('audit-list').append(node('li', 'Your activity will appear here.')); for (const event of result.events.slice(0, 8)) { const row = node('li'); row.append(node('span', event.action.replaceAll('_', ' ') + (event.object_id ? ' · Field ' + event.object_id : '') + (event.detail ? ' · ' + event.detail : '')), node('time', event.created)); $('audit-list').append(row); } }
$('login-form').addEventListener('submit', async (event) => { event.preventDefault(); const button = event.submitter; button.disabled = true; try { const result = await api('/api/login', 'POST', {username: $('username').value, password: $('password').value}); $('password').value = ''; state.csrf = result.csrf; await session(); notice('Welcome to your fieldwork desk.'); } catch (error) { notice(error.message, true); } finally { button.disabled = false; } });
$('logout').addEventListener('click', async () => { try { await api('/api/logout', 'POST', {}); showLogin(); } catch (error) { notice(error.message, true); } });
for (const button of document.querySelectorAll('[data-filter]')) button.addEventListener('click', () => { state.filter = button.dataset.filter; for (const item of document.querySelectorAll('[data-filter]')) item.classList.toggle('selected', item === button); render(); });
$('search').addEventListener('input', render);
$('new-permit').addEventListener('click', () => { $('create-overlay').hidden = false; $('species').focus(); });
function closeCreate() { $('create-overlay').hidden = true; $('new-permit').focus(); }
$('cancel-create').addEventListener('click', closeCreate);
document.addEventListener('keydown', event => { if (event.key === 'Escape' && !$('create-overlay').hidden) closeCreate(); });
$('create-form').addEventListener('submit', async (event) => { event.preventDefault(); const button = event.submitter; button.disabled = true; try { const result = await api('/api/permits', 'POST', {species: $('species').value, location: $('location').value, purpose: $('purpose').value}); state.selected = result.id; $('create-form').reset(); closeCreate(); await loadPermits(); notice('Proposal submitted for independent review.'); } catch (error) { notice(error.message, true); } finally { button.disabled = false; } });
$('refresh-audit').addEventListener('click', () => loadAudit().catch(error => notice(error.message, true)));
session().catch(() => showLogin());
