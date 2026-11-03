/* NCM PLANTS website.
   Data: the server (ncm-web-export\web_export.py) pushes encrypted sections to the "data" branch every
   5 minutes. users.json (main branch) holds each user's key, wrapped with their password; keyring.json
   (data branch) holds, per user, the section keys the admin allowed them. Nothing is readable without
   a password, and each person only gets the keys of their own screens and plants. */
'use strict';
const REPO = 'hadaad11/ncm-plants';
const RAW = `https://raw.githubusercontent.com/${REPO}/refs/heads/`;
const LOCAL = new URLSearchParams(location.search).has('local');      // testing next to the export folder

/* ------------------------------------------------------------------ small helpers */
const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
const fmt = (n, d = 1) => (n === null || n === undefined || n === '' || isNaN(n)) ? '' : Number(n).toLocaleString('en-US', {maximumFractionDigits: d});
const sum = (a, f) => a.reduce((s, r) => s + (+f(r) || 0), 0);
let LANG = 'en';
try { LANG = localStorage.ncmLang || 'en'; } catch (e) {}
const L = s => { const [en, ar] = String(s).split('|'); return LANG === 'ar' && ar ? ar : en; };
function toast(m) { const t = $('toast'); t.textContent = m; t.classList.add('show'); clearTimeout(toast.h); toast.h = setTimeout(() => t.classList.remove('show'), 2600); }
function applyLang() {
  document.documentElement.lang = LANG; document.documentElement.dir = LANG === 'ar' ? 'rtl' : 'ltr';
  document.querySelectorAll('[data-t]').forEach(e => e.textContent = L(e.dataset.t));
  ['langBtn', 'langBtn0'].forEach(id => $(id).textContent = LANG === 'ar' ? 'English' : 'عربي');
}
function toggleLang() { LANG = LANG === 'ar' ? 'en' : 'ar'; try { localStorage.ncmLang = LANG; } catch (e) {} applyLang(); if (S.ring) { buildNav(); show(cur); } }
function toggleTheme() {
  const r = document.documentElement, dark = r.dataset.theme === 'dark' || (!r.dataset.theme && matchMedia('(prefers-color-scheme:dark)').matches);
  r.dataset.theme = dark ? 'light' : 'dark'; try { localStorage.ncmTheme = r.dataset.theme; } catch (e) {}
  if (S.ring) show(cur);
}
try { if (localStorage.ncmTheme) document.documentElement.dataset.theme = localStorage.ncmTheme; } catch (e) {}

/* ------------------------------------------------------------------ crypto (Web Crypto) */
const enc = new TextEncoder(), dec = new TextDecoder();
const ub64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const b64 = b => { let s = ''; new Uint8Array(b).forEach(c => s += String.fromCharCode(c)); return btoa(s); };
async function sha256hex(s) { return [...new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(s)))].map(b => b.toString(16).padStart(2, '0')).join(''); }
async function pwKey(pw, salt, iter) {
  const base = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({name: 'PBKDF2', hash: 'SHA-256', salt, iterations: iter}, base, {name: 'AES-GCM', length: 256}, false, ['encrypt', 'decrypt']);
}
const aesKey = raw => crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
async function open(key, box) { return new Uint8Array(await crypto.subtle.decrypt({name: 'AES-GCM', iv: ub64(box.iv)}, key, ub64(box.ct))); }
async function openJson(key, box) { return JSON.parse(dec.decode(await open(key, box))); }
async function sealBytes(key, bytes) { const iv = crypto.getRandomValues(new Uint8Array(12)); return {iv: b64(iv), ct: b64(await crypto.subtle.encrypt({name: 'AES-GCM', iv}, key, bytes))}; }

/* ------------------------------------------------------------------ state */
const S = {uid: '', k: null, kRaw: null, meta: null, ring: null, data: {}, gen: ''};
const F = {plant: '', from: '', to: '', period: 'month', q: ''};          // shared filters
let cur = 'dash';

async function getJson(url, noCache = true) {
  const r = await fetch(url + (noCache ? (url.includes('?') ? '&' : '?') + 't=' + Date.now() : ''), {cache: 'no-store'});
  if (!r.ok) throw new Error(r.status + ' ' + url.split('/').pop());
  return r.json();
}
const dataUrl = f => LOCAL ? 'data/' + f : RAW + 'data/' + f;
const usersUrl = () => LOCAL ? 'users.json' : RAW + 'main/users.json';

/* ------------------------------------------------------------------ login */
$('lf').onsubmit = async e => {
  e.preventDefault();
  const u = $('lu').value.trim().toLowerCase(), pw = $('lp').value;
  $('lerr').textContent = ''; $('lbtn').disabled = true; $('lbtn').textContent = L('Checking…|جاري التحقق…');
  try {
    const users = (await getJson(usersUrl())).users || [];
    const uid = await sha256hex(u), rec = users.find(x => x.uid === uid);
    if (!rec) throw new Error('bad');
    let kRaw;
    try { kRaw = await open(await pwKey(pw, ub64(rec.salt), rec.iter), rec.pw_box); } catch (x) { throw new Error('bad'); }
    S.uid = uid; S.kRaw = kRaw; S.k = await aesKey(kRaw);
    try { sessionStorage.ncmS = JSON.stringify({uid, k: b64(kRaw)}); } catch (x) {}
    $('lp').value = '';
    await start();
  } catch (x) {
    $('lerr').textContent = x.message === 'bad' ? L('Wrong username or password|اسم المستخدم أو كلمة السر غلط') : x.message;
  } finally { $('lbtn').disabled = false; $('lbtn').textContent = L('Sign in|دخول'); }
};

async function start() {
  await refresh(true);
  $('login').style.display = 'none'; $('app').style.display = 'grid';
  buildNav(); show(SCREENS.some(s => s.id === cur && can(s)) ? cur : (SCREENS.find(can) || {}).id);
  clearInterval(start.h); start.h = setInterval(() => refresh(false), 120000);
}

async function refresh(force) {
  const meta = await getJson(dataUrl('meta.json'));
  if (!force && meta.generated === S.gen) return;
  const ring = await getJson(dataUrl('keyring.json'));
  const box = ring[S.uid];
  if (!box) throw new Error(L('Your account is not active yet (it is ready within 5 minutes of being created) or it was stopped by the admin.|حسابك لسه ما اتفعّلش (بيجهز خلال 5 دقايق من إنشائه) أو الأدمن وقفه.'));
  S.ring = await openJson(S.k, box);
  S.meta = meta;
  try { S.settings = await getJson(LOCAL ? 'settings.json' : RAW + 'main/settings.json'); } catch (e) { S.settings = {hidden: []}; }
  const keys = S.ring.keys || {}, data = {};
  await Promise.all(Object.entries(keys).map(async ([sid, k]) => {
    if (!meta.files[sid]) return;
    try { data[sid] = await openJson(await aesKey(ub64(k)), await getJson(dataUrl(meta.files[sid]))); }
    catch (e) { console.warn(sid, e); }
  }));
  S.data = data; S.gen = meta.generated;
  if (!F.from) { F.to = meta.to; F.from = meta.to; }
  if (!force && $('app').style.display === 'grid') { show(cur, true); toast(L('Data updated|البيانات اتحدثت')); }
  $('meName').textContent = S.ring.name || '';
  $('meAv').textContent = (S.ring.name || 'N').trim()[0].toUpperCase();
  $('meSub').textContent = S.ring.admin ? L('Admin|أدمن') : L('Viewer|مشاهد');
}

function logout() {
  try { sessionStorage.removeItem('ncmS'); } catch (e) {}
  location.reload();
}

/* ------------------------------------------------------------------ data access */
const plantsOf = sec => (S.meta?.plants || []).filter(p => S.data[sec + ':' + p.id]);
const plantName = id => (S.meta.plants.find(p => p.id === id) || {}).label || id;
function rows(p) {                                  // packed table -> array of objects
  if (!p || !p.r) return [];
  const n = new Set(p.n);
  return p.r.map(r => { const o = {}; p.f.forEach((f, i) => o[f] = n.has(i) ? r[i] : p.s[r[i]]); return o; });
}
function isoDay(s) {                                // the plants give "2026-10-31", "31.10.2026" or "31/10/2026"
  s = String(s || '').trim();
  let m = s.match(/^(\d{4})-(\d{2})-(\d{2})/); if (m) return m[0];
  m = s.match(/^(\d{1,2})[./](\d{1,2})[./](\d{4})/); if (m) return `${m[3]}-${m[2].padStart(2, '0')}-${m[1].padStart(2, '0')}`;
  return s.slice(0, 10);
}
const egDay = d => { const m = String(d).match(/^(\d{4})-(\d{2})-(\d{2})/); return m ? `${m[3]}/${m[2]}/${m[1]}` : d; };
function plantRows(sec, pick) {                     // rows from every allowed plant (or the chosen one), with _p
  const out = [];
  for (const p of plantsOf(sec)) {
    if (F.plant && F.plant !== p.id) continue;
    rows(pick(S.data[sec + ':' + p.id])).forEach(r => { r._p = p.label; out.push(r); });
  }
  return out;
}
// Date + optional time, like the program's From / To boxes: the "To" minute counts in full (08:00 -> 08:00:59).
const hhmm = s => (String(s || '').match(/(\d{1,2}):(\d{2})/) || []).slice(1).map(x => x.padStart(2, '0')).join(':');
const stamp = (d, t) => isoDay(d) + ' ' + (hhmm(t) || hhmm(String(d).slice(10)) || '00:00');
const inRange = (d, t) => {
  const s = stamp(d, t), a = (F.from || '0000-00-00') + ' ' + (F.fromT || '00:00'), b = (F.to || '9999-99-99') + ' ' + (F.toT || '23:59');
  return s >= a && s <= b;
};
// filter on the delivery-note time (IrsSaat), like the program; the Time column shows the batch start
const deliveries = () => plantRows('prod', d => d.uretim).filter(r => inRange(r.Tarih, r.IrsSaat || r.Saat));

/* ------------------------------------------------------------------ screens */
const SCREENS = [
  {id: 'dash', sec: 'prod', ic: 'grid', t: 'Dashboard|الرئيسية', sub: 'Overview of all plants|نظرة سريعة على المحطات', r: rDash},
  {id: 'hq', sec: 'prod', ic: 'factory', t: 'Plant Quantity|كميات المحطات', sub: 'Production by plant|الإنتاج لكل محطة', r: rPlantQty},
  {id: 'del', sec: 'prod', ic: 'truck', t: 'Deliveries|الرحلات', sub: 'Every delivery note|كل الرحلات بالتفصيل', r: rDeliveries},
  {id: 'cust', sec: 'prod', ic: 'users', t: 'Customer Summary|ملخص العملاء', sub: 'm³ per customer, site and mix|الكميات لكل عميل وموقع وخلطة', r: rCustomers},
  {id: 'ret', sec: 'prod', ic: 'back', t: 'Returned Concrete|الخرسانة المرتجعة', sub: 'Returned, reused and wasted m³|المرتجع والمستخدم والهالك', r: rReturned},
  {id: 'tm', sec: 'prod', ic: 'truck', t: 'Truck Mixers|الخلاطات', sub: 'Trips and m³ per truck|الرحلات والكميات لكل عربية', r: rTrucks},
  {id: 'mat', sec: 'mat', ic: 'cube', t: 'Material Consumption|استهلاك المواد', sub: 'kg per material|الكيلوجرامات لكل مادة', r: () => rMat('malzeme')},
  {id: 'hedef', sec: 'mat', ic: 'scale', t: 'Target vs Actual|المستهدف والفعلي', sub: 'Target and actual kg per material|المستهدف والفعلي لكل مادة', r: () => rMat('hedef')},
  {id: 'formul', sec: 'mat', ic: 'flask', t: 'Formula Control|مراجعة الخلطات', sub: 'Theory vs real per formula|النظري مقابل الفعلي لكل خلطة', r: () => rMat('formul')},
  {id: 'mix', sec: 'mix', ic: 'doc', t: 'Mix Designs|تصميمات الخلطات', sub: 'kg/m³ of every recipe|كيلو/م³ لكل خلطة', r: rMix},
  {id: 'cons', sec: 'cons', ic: 'list', t: 'Consumption|الاستهلاك', sub: 'Mix Theory vs Dry Real|النظري مقابل الفعلي', r: rCons},
  // with the NCM Hub permission these show the hub's own pages (aging, grease…), otherwise the sheets as tables
  {id: 'cement', sec: 'cement', ic: 'silo', t: 'Cement|الأسمنت', sub: 'Cement tracking|متابعة الأسمنت', r: () => rSheet('cement')},
  {id: 'manpower', sec: 'manpower', ic: 'users', t: 'Manpower|المانباور', sub: 'Staff and shifts|العمالة والورديات', r: () => rSheet('manpower')},
  {id: 'maint', sec: 'maint', ic: 'wrench', t: 'Maintenance|الصيانة', sub: 'Maintenance and grease|الصيانة والشحم', r: () => rSheet('maint')},
  {id: 'monitor', sec: 'monitor', ic: 'pulse', t: 'Monitor|المونيتور', sub: 'Server and network|حالة السيرفر والشبكة', r: rMonitor},
  // outside pages that were in the NCM Hub (permission "Pour Tracker & Ice")
  {id: 'pour', sec: 'hub', ic: 'truck', t: 'Pour Tracker|متابعة الصبات', sub: 'Pours and requests|الصبات والطلبات', r: v => rFrame(v, 'https://hadaad11.github.io/pourtracker-/')},
  {id: 'ice', sec: 'hub', ic: 'cube', t: 'Ice Calculate|حساب التلج', sub: 'Ice for the mix temperature|التلج لدرجة حرارة الخلطة', r: v => rFrame(v, 'https://elkady591.github.io/Ice-Calculator/')},
  {id: 'users', admin: true, ic: 'shield', t: 'Admin · Users|الأدمن · المستخدمين', sub: 'Add users, passwords and who sees what|إضافة المستخدمين وكلمات السر ومين يشوف إيه', r: rUsers},
];
const hidden = s => (S.settings?.hidden || []).includes(s.id);     // switched off in Admin > Settings
const can = s => s.admin ? !!S.ring?.admin : !hidden(s) &&           // hidden = gone for everyone, admin too
  (['prod', 'mat', 'mix'].includes(s.sec) ? plantsOf(s.sec).length > 0 : !!S.data[s.sec]);

function buildNav() {
  $('nav').innerHTML = SCREENS.filter(can).map(s => (s.admin ? '<div class="sep"></div>' : '') +
    `<button data-p="${s.id}" class="${s.admin ? 'admin' : ''}"><svg class="i"><use href="#i-${s.ic}"/></svg>${L(s.t)}</button>`).join('') ||
    `<div class="empty">${L('The admin did not give you any screen yet.|الأدمن لسه ما اداكش أي شاشة.')}</div>`;
  $('nav').querySelectorAll('button').forEach(b => b.onclick = () => { show(b.dataset.p); $('side').classList.remove('open'); });
}
const charts = {};
function show(id, keep) {
  const s = SCREENS.find(x => x.id === id && can(x)); if (!s) return;
  cur = id;
  $('nav').querySelectorAll('button').forEach(b => b.classList.toggle('on', b.dataset.p === id));
  $('pTitle').textContent = L(s.t); $('pSub').textContent = L(s.sub);
  Object.values(charts).forEach(c => c.destroy()); for (const k in charts) delete charts[k];
  const v = $('view'); const y = keep ? window.scrollY : 0;
  v.innerHTML = ''; v.classList.remove('on'); void v.offsetWidth; v.classList.add('on');
  try { s.r(v); } catch (e) { console.error(e); v.innerHTML = `<div class="panel glass empty">${esc(e.message)}</div>`; }
  window.scrollTo(0, y);
  const g = new Date(S.meta.generated);
  $('foot').textContent = L('Data from the plants at|آخر تحديث من المحطات') + ' ' + g.toLocaleString('en-GB', {day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit'}) +
    (S.meta.down?.length ? ' · ⚠ ' + L('not reachable|مش متاحة') + ': ' + S.meta.down.join(', ') : '');
}

/* ---------- shared filter bar ---------- */
function filterBar(el, opts, redraw) {
  const plants = plantsOf(opts.sec);
  const bar = document.createElement('div'); bar.className = 'panel glass';
  bar.innerHTML = `<div class="tbar" style="margin:0">
    ${opts.dates ? `<span class="note">${L('From|من')}</span><input type="date" id="fFrom" min="${S.meta.from}" max="${S.meta.to}" value="${F.from}">
    ${opts.time ? `<input type="time" id="fFromT" value="${F.fromT || ''}" title="${L('Start hour (empty = 00:00)|ساعة البداية (فاضي = 00:00)')}">` : ''}
    <span class="note">${L('To|إلى')}</span><input type="date" id="fTo" min="${S.meta.from}" max="${S.meta.to}" value="${F.to}">
    ${opts.time ? `<input type="time" id="fToT" value="${F.toT || ''}" title="${L('End hour (empty = end of day)|ساعة النهاية (فاضي = آخر اليوم)')}">` : ''}
    <div class="seg" id="fQuick">${[['today', 'Today|النهارده'], ['yday', 'Yesterday|امبارح'], ...(opts.time ? [['d8', '8 AM → 8 AM|٨ص ← ٨ص']] : []), ['month', 'This month|الشهر ده'], ['last', 'Last month|الشهر اللي فات']].map(([k, t]) => `<button data-k="${k}">${L(t)}</button>`).join('')}</div>` : ''}
    ${opts.period ? `<div class="seg" id="fPer">${[['today', 'Today|النهارده'], ['yesterday', 'Yesterday|امبارح'], ['day8', '8 AM → 8 AM|٨ص ← ٨ص'], ['month', 'This month|الشهر ده'], ['lastmonth', 'Last month|الشهر اللي فات']].filter(([k]) => S.meta.periods?.[k]).map(([k, t]) => `<button data-k="${k}" class="${F.period === k ? 'on' : ''}">${L(t)}</button>`).join('')}</div>` : ''}
    ${plants.length > 1 || opts.plantList ? `<select id="fPlant"><option value="">${L('All plants|كل المحطات')}</option>${(opts.plantList || plants.map(p => [p.id, p.label])).map(([v, t]) => `<option value="${esc(v)}" ${F.plant === v ? 'selected' : ''}>${esc(t)}</option>`).join('')}</select>` : ''}
  </div>`;
  el.appendChild(bar);
  const q = id => bar.querySelector('#' + id);
  if (opts.dates) {
    q('fFrom').onchange = e => { F.from = e.target.value; redraw(); };
    q('fTo').onchange = e => { F.to = e.target.value; redraw(); };
    q('fQuick').onclick = e => {
      const k = e.target.dataset.k; if (!k) return;
      const t = new Date(S.meta.to + 'T00:00'), d = x => x.toISOString().slice(0, 10), y = new Date(t); y.setDate(y.getDate() - 1);
      const m1 = S.meta.to.slice(0, 8) + '01', lm = new Date(t.getFullYear(), t.getMonth(), 0);
      const yd = d(new Date(y.getTime() - y.getTimezoneOffset() * 6e4));
      [F.from, F.to] = {today: [S.meta.to, S.meta.to], yday: [yd, yd], d8: [yd, S.meta.to],
        month: [m1, S.meta.to], last: [S.meta.from, `${lm.getFullYear()}-${String(lm.getMonth() + 1).padStart(2, '0')}-${String(lm.getDate()).padStart(2, '0')}`]}[k];
      [F.fromT, F.toT] = k === 'd8' ? ['08:00', '08:00'] : ['', ''];
      redraw();
    };
    if (opts.time) {
      q('fFromT').onchange = e => { F.fromT = e.target.value; redraw(); };
      q('fToT').onchange = e => { F.toT = e.target.value; redraw(); };
    }
  }
  if (opts.period) q('fPer').onclick = e => { if (!e.target.dataset.k) return; F.period = e.target.dataset.k; q('fPer').querySelectorAll('button').forEach(b => b.classList.toggle('on', b === e.target)); redraw(); };
  if (q('fPlant')) q('fPlant').onchange = e => { F.plant = e.target.value; redraw(); };
}

/* ---------- generic table ---------- */
function table(el, cols, data, o = {}) {
  const box = document.createElement('div'); box.className = 'panel glass'; el.appendChild(box);
  let sortK = o.sort || null, sortD = o.desc ? -1 : 1, q = '';
  const MAX = 1500;
  function draw() {
    let d = data;
    if (q) { const s = q.toLowerCase(); d = d.filter(r => cols.some(c => String(r[c.k] ?? '').toLowerCase().includes(s))); }
    if (sortK) { const c = cols.find(x => x.k === sortK); d = [...d].sort((a, b) => c?.num ? ((+a[sortK] || 0) - (+b[sortK] || 0)) * sortD : String(a[sortK] ?? '').localeCompare(String(b[sortK] ?? ''), undefined, {numeric: true}) * sortD); }
    const tot = cols.filter(c => c.sum);
    box.querySelector('.cnt').textContent = `${fmt(d.length, 0)} ${L('rows|صف')}` + (d.length > MAX ? ` · ${L('showing the first|معروض أول')} ${MAX}` : '');
    box.querySelector('tbody').innerHTML = d.slice(0, MAX).map(r => '<tr>' + cols.map(c => `<td class="${c.num ? 'n' : ''}">${c.f ? c.f(r[c.k], r) : c.num ? fmt(r[c.k], c.d ?? 1) : esc(r[c.k])}</td>`).join('') + '</tr>').join('') ||
      `<tr><td colspan="${cols.length}" class="empty">${L('No data for this choice|مفيش بيانات للاختيار ده')}</td></tr>`;
    box.querySelector('tfoot').innerHTML = tot.length && d.length ? '<tr>' + cols.map((c, i) => `<td class="${c.num ? 'n' : ''}">${c.sum ? fmt(typeof c.sum === 'function' ? c.sum(d) : sum(d, r => r[c.k]), c.d ?? 1) : i === 0 ? L('Total|الإجمالي') : ''}</td>`).join('') + '</tr>' : '';
    box._rows = d;
  }
  box.innerHTML = `${o.title ? `<h3>${o.title}</h3>` : ''}<div class="tbar"><input placeholder="${L('Search…|بحث…')}" class="tq"><span class="grow"></span><span class="cnt"></span><button class="btn sm csv">CSV</button></div>
    <div class="tw"><table><thead><tr>${cols.map(c => `<th class="${c.num ? 'n' : ''}" data-k="${c.k}">${L(c.l)}</th>`).join('')}</tr></thead><tbody></tbody><tfoot></tfoot></table></div>`;
  box.querySelector('.tq').oninput = e => { q = e.target.value; draw(); };
  box.querySelector('thead').onclick = e => { const k = e.target.dataset.k; if (!k) return; sortD = sortK === k ? -sortD : (cols.find(c => c.k === k).num ? -1 : 1); sortK = k; draw(); };
  box.querySelector('.csv').onclick = () => {
    const lines = [cols.map(c => L(c.l)), ...box._rows.map(r => cols.map(c => r[c.k] ?? ''))].map(a => a.map(v => `"${String(v).replace(/"/g, '""')}"`).join(','));
    const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob(['﻿' + lines.join('\r\n')], {type: 'text/csv'}));
    a.download = (o.file || cur) + '.csv'; a.click();
  };
  draw();
  return box;
}
function group(data, keys, nums) {
  const m = new Map();
  for (const r of data) {
    const k = keys.map(x => r[x]).join('\u0001');
    let g = m.get(k); if (!g) { g = {_n: 0}; keys.forEach(x => g[x] = r[x]); nums.forEach(x => g[x] = 0); m.set(k, g); }
    g._n++; nums.forEach(x => g[x] += +r[x] || 0);
  }
  return [...m.values()];
}
function chart(el, id, cfg, h = 280) {
  const box = document.createElement('div'); box.className = 'chartbox'; box.style.height = h + 'px';
  box.innerHTML = `<canvas id="${id}"></canvas>`; el.appendChild(box);
  const css = v => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
  Chart.defaults.font.family = 'Cairo'; Chart.defaults.color = css('--ink2');
  cfg.options = Object.assign({responsive: true, maintainAspectRatio: false, interaction: {mode: 'index', intersect: false},
    plugins: {legend: {position: 'bottom', labels: {usePointStyle: true, boxWidth: 8}}}}, cfg.options || {});
  charts[id] = new Chart(box.querySelector('canvas'), cfg);
}
const PC = ['#0067a8', '#1ba352', '#2f8fd8', '#7d7d7d', '#4cc77d', '#e3a21a', '#8e5bd8'];
const panel = (el, title) => { const p = document.createElement('div'); p.className = 'panel glass'; p.innerHTML = title ? `<h3>${title}</h3>` : ''; el.appendChild(p); return p; };

/* ---------- dashboard ---------- */
let span = 14;
function rDash(v) {
  const ps = plantsOf('prod'), k = (p, per, i) => +(S.data['prod:' + p.id].kpi?.[per]?.[i] || 0);
  const today = sum(ps, p => k(p, 'today', 1)), trips = sum(ps, p => k(p, 'today', 0)), month = sum(ps, p => k(p, 'month', 1));
  const up = ps.filter(p => !(S.meta.down || []).includes(p.label)).length;
  const kp = document.createElement('div'); kp.className = 'kpis'; v.appendChild(kp);
  kp.innerHTML = [[L('Today|النهارده'), fmt(today) + ' m³', 'cube', 'var(--blue)', 'del'], [L('Trips today|رحلات النهارده'), fmt(trips, 0), 'truck', 'var(--green)', 'del'],
    [L('Month to date|من أول الشهر'), fmt(month, 0) + ' m³', 'factory', '#2f8fd8', 'cust'], [L('Plants online|المحطات الشغالة'), `${up} / ${ps.length}`, 'pulse', '#7d7d7d', 'monitor']]
    .map(([l, val, ic, c, g]) => `<div class="kpi glass" data-g="${g}"><div class="h"><span class="ic" style="background:${c}"><svg class="i"><use href="#i-${ic}"/></svg></span>${l}</div><div class="v">${val}</div></div>`).join('');
  kp.onclick = e => { const g = e.target.closest('.kpi')?.dataset.g; if (g && SCREENS.some(s => s.id === g && can(s))) { if (g === 'del') { F.from = F.to = S.meta.to; } show(g); } };

  const g2 = document.createElement('div'); g2.className = 'grid2'; v.appendChild(g2);
  const pc = panel(g2, `<span>${L('Daily production (m³)|الإنتاج اليومي (م³)')}</span><div class="seg" id="rng">${[7, 14, 31].map(n => `<button data-d="${n}" class="${n === span ? 'on' : ''}">${n}</button>`).join('')}</div>`);
  const days = []; for (let i = span - 1; i >= 0; i--) { const d = new Date(S.meta.to + 'T00:00'); d.setDate(d.getDate() - i); days.push(d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0')); }
  chart(pc, 'cProd', {type: 'bar', data: {labels: days.map(d => d.slice(8) + '/' + d.slice(5, 7)), datasets: ps.map((p, i) => {
    const m = {}; rows(S.data['prod:' + p.id].gunluk).forEach(r => m[isoDay(r.Tarih)] = +r.M3 || 0);
    return {label: p.label, data: days.map(d => m[d] || 0), backgroundColor: PC[i % PC.length], borderRadius: 6, stack: 's'};
  })}, options: {scales: {x: {stacked: true, grid: {display: false}}, y: {stacked: true, grid: {color: 'rgba(125,125,125,.15)'}}}}});
  pc.querySelector('#rng').onclick = e => { if (e.target.dataset.d) { span = +e.target.dataset.d; show('dash', true); } };

  const pa = panel(g2, L('Latest deliveries|آخر الرحلات'));
  const last = plantRows('prod', d => d.uretim).sort((a, b) => (isoDay(b.Tarih) + b.Saat).localeCompare(isoDay(a.Tarih) + a.Saat)).slice(0, 7);
  pa.innerHTML += `<ul class="act">${last.map((r, i) => `<li><span class="dot" style="background:${PC[i % PC.length]}"></span><div><b>${fmt(r.ReelM3 || r.SiparisM3)} m³ — ${esc(r._p)} · ${esc(r.FormulKodu || r.Urun)}</b><small>${esc(r.Musteri)} · ${esc(r.Santiye)} · ${egDay(isoDay(r.Tarih))} ${esc(String(r.Saat).slice(0, 5))}</small></div></li>`).join('') || `<li class="empty">—</li>`}</ul>`;

  const pl = document.createElement('div'); pl.className = 'plants'; v.appendChild(pl);
  const max = Math.max(1, ...ps.map(p => k(p, 'today', 1)));
  pl.innerHTML = ps.map(p => { const m3 = k(p, 'today', 1), pct = Math.round(m3 / max * 100), down = (S.meta.down || []).includes(p.label);
    return `<div class="pl glass" data-p="${p.id}"><div class="n">${esc(p.label)} ${down ? '<span class="pill off">off</span>' : ''}</div><div class="ring" style="--p:${pct}" data-t="${fmt(k(p, 'today', 0), 0)} ${L('trips|رحلة')}"></div><div class="m">${fmt(m3)}</div><small>m³ ${L('today|النهارده')}</small></div>`; }).join('');
  pl.onclick = e => { const p = e.target.closest('.pl')?.dataset.p; if (p) { F.plant = p; F.from = F.to = S.meta.to; show('del'); } };
}

/* ---------- production screens ---------- */
function rDeliveries(v) {
  const redraw = () => show('del', true);
  filterBar(v, {sec: 'prod', dates: true, time: true}, redraw);
  const d = deliveries();
  table(v, [
    {k: 'Tarih', l: 'Date|التاريخ', f: x => egDay(isoDay(x))}, {k: 'Saat', l: 'Time|الوقت', f: x => esc(String(x).slice(0, 5))}, {k: '_p', l: 'Plant|المحطة'},
    {k: 'IrsaliyeNo', l: 'Delivery No|رقم الإذن'}, {k: 'Musteri', l: 'Customer|العميل'}, {k: 'Santiye', l: 'Site|الموقع'},
    {k: 'FormulKodu', l: 'Mix Code|كود الخلطة'}, {k: 'Urun', l: 'Product|المنتج'}, {k: 'SiparisM3', l: 'Ordered m³|المطلوب م³', num: 1, sum: 1},
    {k: 'ReelM3', l: 'Actual m³|الفعلي م³', num: 1, sum: 1}, {k: 'ReelCimento', l: 'Cement kg|أسمنت كجم', num: 1, d: 0, sum: 1}, {k: 'ReelSu', l: 'Water kg|مياه كجم', num: 1, d: 0, sum: 1},
    {k: 'Sofor', l: 'Driver|السواق'}, {k: 'Plaka', l: 'Plate|العربية'}], d, {sort: 'Tarih', desc: 1, file: 'deliveries'});
}
function rPlantQty(v) {
  filterBar(v, {sec: 'prod', dates: true, time: true}, () => show('hq', true));
  const d = deliveries();
  const g = group(d, ['_p'], ['SiparisM3', 'ReelM3', 'ReelCimento', 'ReelSu']);
  const pc = panel(v, L('m³ per plant|م³ لكل محطة'));
  chart(pc, 'cPQ', {type: 'bar', data: {labels: g.map(r => r._p), datasets: [
    {label: L('Ordered m³|المطلوب م³'), data: g.map(r => r.SiparisM3), backgroundColor: '#0067a8', borderRadius: 6},
    {label: L('Actual m³|الفعلي م³'), data: g.map(r => r.ReelM3), backgroundColor: '#1ba352', borderRadius: 6}]},
    options: {scales: {x: {grid: {display: false}}, y: {grid: {color: 'rgba(125,125,125,.15)'}}}}}, 240);
  table(v, [{k: '_p', l: 'Plant|المحطة'}, {k: '_n', l: 'Trips|الرحلات', num: 1, d: 0, sum: 1}, {k: 'SiparisM3', l: 'Ordered m³|المطلوب م³', num: 1, sum: 1},
    {k: 'ReelM3', l: 'Actual m³|الفعلي م³', num: 1, sum: 1}, {k: 'ReelCimento', l: 'Cement kg|أسمنت كجم', num: 1, d: 0, sum: 1}, {k: 'ReelSu', l: 'Water kg|مياه كجم', num: 1, d: 0, sum: 1}],
    g, {sort: '_p', file: 'plant-quantity', title: L('Per plant|لكل محطة')});
  // day x plant (by delivery-note date)
  const plants = [...new Set(d.map(r => r._p))].sort(), days = {};
  d.forEach(r => { const k = isoDay(r.Tarih); (days[k] = days[k] || {_d: k, _t: 0})[r._p] = (days[k][r._p] || 0) + (+r.SiparisM3 || 0); days[k]._t += +r.SiparisM3 || 0; });
  table(v, [{k: '_d', l: 'Date|التاريخ', f: x => egDay(x)}, ...plants.map(p => ({k: p, l: p, num: 1, sum: 1})), {k: '_t', l: 'Total|الإجمالي', num: 1, sum: 1}],
    Object.values(days), {sort: '_d', desc: 1, file: 'plant-quantity-by-day', title: L('By day (m³)|حسب اليوم (م³)')});
}
function rCustomers(v) {
  filterBar(v, {sec: 'prod', dates: true, time: true}, () => show('cust', true));
  const g = group(deliveries(), ['Musteri', 'Santiye', 'Urun', 'FormulKodu'], ['SiparisM3', 'ReelM3']);
  const top = group(deliveries(), ['Musteri'], ['SiparisM3']).sort((a, b) => b.SiparisM3 - a.SiparisM3).slice(0, 10);
  const pc = panel(v, L('Top customers (m³)|أكبر العملاء (م³)'));
  chart(pc, 'cCust', {type: 'bar', data: {labels: top.map(r => r.Musteri), datasets: [{label: 'm³', data: top.map(r => r.SiparisM3), backgroundColor: '#0067a8', borderRadius: 6}]},
    options: {indexAxis: 'y', plugins: {legend: {display: false}}, scales: {x: {grid: {color: 'rgba(125,125,125,.15)'}}, y: {grid: {display: false}}}}}, Math.max(180, top.length * 30));
  table(v, [{k: 'Musteri', l: 'Customer|العميل'}, {k: 'Santiye', l: 'Site|الموقع'}, {k: 'Urun', l: 'Product|المنتج'}, {k: 'FormulKodu', l: 'Mix Code|كود الخلطة'},
    {k: '_n', l: 'Deliveries|الرحلات', num: 1, d: 0, sum: 1}, {k: 'SiparisM3', l: 'Total m³|الإجمالي م³', num: 1, sum: 1}, {k: 'ReelM3', l: 'Actual m³|الفعلي م³', num: 1, sum: 1}], g, {sort: 'SiparisM3', desc: 1, file: 'customers'});
}
function rReturned(v) {
  filterBar(v, {sec: 'prod', dates: true, time: true}, () => show('ret', true));
  const d = plantRows('prod', x => x.iade).filter(r => inRange(r.Tarih, r.IrsSaat));
  table(v, [{k: 'Tarih', l: 'Date|التاريخ', f: x => egDay(isoDay(x))}, {k: '_p', l: 'Plant|المحطة'}, {k: 'IrsaliyeNo', l: 'Delivery No|رقم الإذن'}, {k: 'Musteri', l: 'Customer|العميل'},
    {k: 'Santiye', l: 'Site|الموقع'}, {k: 'Urun', l: 'Product|المنتج'}, {k: 'IadeM3', l: 'Returned m³|المرتجع م³', num: 1, sum: 1}, {k: 'KullanilanM3', l: 'Reused m³|المستخدم م³', num: 1, sum: 1},
    {k: 'KalanM3', l: 'Wasted m³|الهالك م³', num: 1, sum: 1}, {k: 'Plaka', l: 'Plate|العربية'}], d, {sort: 'Tarih', desc: 1, file: 'returned'});
}
function rTrucks(v) {
  filterBar(v, {sec: 'prod', dates: true, time: true}, () => show('tm', true));
  const g = group(deliveries(), ['Plaka'], ['SiparisM3', 'ReelM3']).map(r => (r.avg = r.SiparisM3 / r._n, r));
  table(v, [{k: 'Plaka', l: 'Plate|العربية'}, {k: '_n', l: 'Trips|الرحلات', num: 1, d: 0, sum: 1}, {k: 'SiparisM3', l: 'Total m³|الإجمالي م³', num: 1, sum: 1},
    {k: 'ReelM3', l: 'Actual m³|الفعلي م³', num: 1, sum: 1}, {k: 'avg', l: 'Avg m³/trip|متوسط م³/رحلة', num: 1, d: 2}], g, {sort: '_n', desc: 1, file: 'truck-mixers'});
}

/* ---------- material screens (fixed periods, computed on the server) ---------- */
function rMat(kind) {
  const v = $('view');
  filterBar(v, {sec: 'mat', period: true}, () => show(cur, true));
  const d = plantRows('mat', x => x[F.period]?.[kind]);
  const per = S.meta.periods?.[F.period];
  if (per) panel(v).innerHTML = `<div class="note">${L('Period|الفترة')}: ${egDay(per[0].slice(0, 10))} ${per[0].slice(11, 16)} → ${egDay(per[1].slice(0, 10))} ${per[1].slice(11, 16)}
    · ${L('Material screens use fixed periods computed on the server; for any other hours use Deliveries.|شاشات المواد بفترات ثابتة محسوبة على السيرفر؛ لأي ساعات تانية استخدم شاشة الرحلات.')}</div>`;
  if (kind === 'malzeme') {
    const g = group(d, ['Kod', 'Malzeme', 'Grup'], ['ToplamKg']);
    table(v, [{k: 'Kod', l: 'Code|الكود'}, {k: 'Malzeme', l: 'Material|المادة'}, {k: 'Grup', l: 'Group|المجموعة'}, {k: 'ToplamKg', l: 'Total (kg)|الإجمالي (كجم)', num: 1, d: 0, sum: 1}], g, {sort: 'ToplamKg', desc: 1, file: 'material'});
  } else if (kind === 'hedef') {
    const g = group(d, ['Kod', 'Malzeme', 'Grup'], ['HedefKg', 'ReelKg']).map(r => (r.FarkKg = r.ReelKg - r.HedefKg, r.FarkYuzde = r.HedefKg ? r.FarkKg / r.HedefKg * 100 : 0, r));
    const pct = x => `<span style="color:${Math.abs(x) > 2 ? 'var(--danger)' : 'var(--green)'};font-weight:700">${fmt(x, 2)}%</span>`;
    table(v, [{k: 'Kod', l: 'Code|الكود'}, {k: 'Malzeme', l: 'Material|المادة'}, {k: 'Grup', l: 'Group|المجموعة'}, {k: 'HedefKg', l: 'Target (kg)|المستهدف', num: 1, d: 0, sum: 1},
      {k: 'ReelKg', l: 'Actual (kg)|الفعلي', num: 1, d: 0, sum: 1}, {k: 'FarkKg', l: 'Diff (kg)|الفرق', num: 1, d: 0, sum: 1}, {k: 'FarkYuzde', l: 'Diff %|الفرق %', num: 1, f: pct}], g, {sort: 'ReelKg', desc: 1, file: 'target-vs-actual'});
  } else {
    const pct = x => `<span style="color:${Math.abs(+x) > 2 ? 'var(--danger)' : 'inherit'}">${fmt(x, 2)}</span>`;
    table(v, [{k: '_p', l: 'Plant|المحطة'}, {k: 'Formul', l: 'Formula|الخلطة'}, {k: 'Urun', l: 'Product|المنتج'}, {k: 'M3', l: 'm³', num: 1}, {k: 'Malzeme', l: 'Material|المادة'}, {k: 'Grup', l: 'Group|المجموعة'},
      {k: 'Teori', l: 'Theory|النظري', num: 1, d: 0}, {k: 'Hedef', l: 'Batch Target|مستهدف الباتش', num: 1, d: 0}, {k: 'Tarti', l: 'Weighed|الموزون', num: 1, d: 0},
      {k: 'NemFarki', l: 'Humidity Dif.|فرق الرطوبة', num: 1, d: 0}, {k: 'KuruReel', l: 'Dry Real|الجاف الفعلي', num: 1, d: 0}, {k: 'Fark', l: 'Difference|الفرق', num: 1, d: 0},
      {k: 'FarkYuzde', l: 'Diff %|الفرق %', num: 1, f: pct}], d, {file: 'formula-control'});
  }
}
function rMix(v) {
  filterBar(v, {sec: 'mix'}, () => show('mix', true));
  const d = plantRows('mix', x => x.tasarim);
  table(v, [{k: '_p', l: 'Plant|المحطة'}, {k: 'Formul', l: 'Formula|الخلطة'}, {k: 'Urun', l: 'Product|المنتج'}, {k: 'Grup', l: 'Group|المجموعة'}, {k: 'Malzeme', l: 'Material|المادة'},
    {k: 'Kilo', l: 'kg / m³', num: 1}, {k: 'SuCimento', l: 'W/C', num: 1, d: 3}, {k: 'Dmax', l: 'Dmax', num: 1}, {k: 'Kivam', l: 'Slump', num: 1}, {k: 'Toplam', l: 'Total kg/m³|الإجمالي', num: 1}], d, {file: 'mix-designs'});
}

/* ---------- consumption (material report sheet) ---------- */
let consView = 'mat';
function rCons(v) {
  const all = rows(S.data.cons);
  const labels = [...new Set(all.map(r => r.Plant))].filter(Boolean).sort();
  filterBar(v, {sec: 'cons', dates: true, plantList: labels.map(x => [x, x])}, () => show('cons', true));
  const d = all.filter(r => inRange(r.Date) && (!F.plant || r.Plant === F.plant));
  const tabs = panel(v); tabs.innerHTML = `<div class="tabs" style="margin:0">${[['mat', 'By material|حسب المادة'], ['mix', 'By mix|حسب الخلطة'], ['day', 'By day|حسب اليوم'], ['plant', 'By plant|حسب المحطة']].map(([k, t]) => `<button data-k="${k}" class="${k === consView ? 'on' : ''}">${L(t)}</button>`).join('')}</div>`;
  tabs.onclick = e => { if (e.target.dataset.k) { consView = e.target.dataset.k; show('cons', true); } };
  const key = {mat: ['Material'], mix: ['Mix'], day: ['Date'], plant: ['Plant']}[consView];
  const g = group(d, key, ['MixTheory', 'DryReal', 'Theory', 'Weighed']).map(r => (r.Diff = r.DryReal - r.MixTheory, r.Pct = r.MixTheory ? r.Diff / r.MixTheory * 100 : 0, r));
  if (consView === 'day') g.sort((a, b) => a.Date.localeCompare(b.Date));
  const pct = x => `<span style="color:${Math.abs(x) > 2 ? 'var(--danger)' : 'var(--green)'};font-weight:700">${fmt(x, 2)}%</span>`;
  table(v, [{k: key[0], l: {Material: 'Material|المادة', Mix: 'Mix|الخلطة', Date: 'Date|التاريخ', Plant: 'Plant|المحطة'}[key[0]], f: consView === 'day' ? x => egDay(x) : null},
    {k: 'MixTheory', l: 'Mix Theory', num: 1, d: 0, sum: 1}, {k: 'DryReal', l: 'Dry Real', num: 1, d: 0, sum: 1}, {k: 'Diff', l: 'Diff|الفرق', num: 1, d: 0, sum: 1},
    {k: 'Pct', l: 'Diff %|الفرق %', num: 1, f: pct}], g, {sort: consView === 'day' ? 'Date' : 'MixTheory', desc: consView !== 'day', file: 'consumption-' + consView});
}

/* ---------- grease dashboard (workbook "استهلاك الشحم.xlsm"; the same views the NCM Hub had) ---------- */
let greaseView = 'summary';
function rGrease(v, d) {
  const tab = w => (Object.entries(d).find(([k]) => k.startsWith('Grease') && k.includes(w)) || [, []])[1];
  const n = x => { const y = typeof x === 'number' ? x : parseFloat(String(x ?? '').replace(/,/g, '')); return isNaN(y) ? null : y; };
  const plant = s => String(s || '').replace(/^محطة\s*/, LANG === 'ar' ? 'محطة ' : 'Plant ').replace(/^الإجمالي$/, L('Total|الإجمالي'));
  const hdr = (rows, first) => rows.findIndex(r => String(r[0] || '').trim() === first);
  const p = panel(v);
  p.innerHTML = `<div class="tabs" style="margin:0">${[['summary', 'Summary|الملخص'], ['daily', 'Daily log|المتابعة اليومية'], ['opening', 'Opening balance|رصيد أول الشهر']]
    .map(([k, t]) => `<button data-g="${k}" class="${k === greaseView ? 'on' : ''}">${L(t)}</button>`).join('')}<span class="grow"></span></div>`;
  p.onclick = e => { if (e.target.dataset.g) { greaseView = e.target.dataset.g; show(cur, true); } };

  if (greaseView === 'summary') {
    const rows = tab('ملخص'), res = {};
    // the results block (label in column E, value in F); the first match wins, the per-plant table below repeats some words
    rows.forEach(r => { const k = String(r[4] || '').trim(); if (k && r[5] !== undefined && r[5] !== '' && !(k in res)) res[k] = r[5]; });
    const get = w => { const k = Object.keys(res).find(x => x.startsWith(w)); return k ? res[k] : null; };
    const kp = document.createElement('div'); kp.className = 'kpis'; v.appendChild(kp);
    kp.innerHTML = [[L('Balance (kg)|الرصيد (كجم)'), fmt(n(get('إجمالي الرصيد'))), 'cube', 'var(--blue)'], [L('Balance (drums)|الرصيد (براميل)'), fmt(n(get('الرصيد الحالي')), 2), 'silo', 'var(--green)'],
      [L('Used this month (kg)|استهلاك الشهر (كجم)'), fmt(n(get('استهلاك الشهر'))), 'pulse', '#2f8fd8'], [L('Days of cover|يكفي (يوم)'), fmt(n(get('مدة كفاية')), 0), 'refresh', '#7d7d7d']]
      .map(([l, val, ic, c]) => `<div class="kpi glass"><div class="h"><span class="ic" style="background:${c}"><svg class="i"><use href="#i-${ic}"/></svg></span>${l}</div><div class="v">${val || '—'}</div></div>`).join('');
    const hi = hdr(rows, 'المحطة');
    const pr = hi >= 0 ? rows.slice(hi + 1).filter(r => /^محطة|^الإجمالي/.test(String(r[0] || ''))) : [];
    const data = pr.map(r => ({p: plant(r[0]), open: n(r[1]), inn: n(r[2]), trucks: n(r[3]), use: n(r[4]), bal: n(r[5]), drum: (n(r[6]) || 0) * 100, days: n(r[8]), tpd: n(r[9]), kpd: n(r[10]), cover: n(r[11]), fc: n(r[12])}));
    const plantsOnly = data.filter(r => !/Total|الإجمالي/.test(r.p));
    if (plantsOnly.length) {
      const pc = panel(v, L('Balance per plant (kg)|الرصيد لكل محطة (كجم)'));
      chart(pc, 'cGr', {type: 'bar', data: {labels: plantsOnly.map(r => r.p), datasets: [{label: L('Balance kg|الرصيد كجم'), data: plantsOnly.map(r => r.bal), backgroundColor: plantsOnly.map(r => (r.bal ?? 0) < 20 ? '#e0533d' : '#1ba352'), borderRadius: 6},
        {label: L('Used kg|المستهلك كجم'), data: plantsOnly.map(r => r.use), backgroundColor: '#0067a8', borderRadius: 6}]}, options: {scales: {x: {grid: {display: false}}, y: {grid: {color: 'rgba(125,125,125,.15)'}}}}}, 240);
    }
    table(v, [{k: 'p', l: 'Plant|المحطة'}, {k: 'open', l: 'Opening (kg)|أول المدة', num: 1}, {k: 'inn', l: 'Received (kg)|الوارد', num: 1}, {k: 'trucks', l: 'Trucks|العربيات', num: 1, d: 0},
      {k: 'use', l: 'Used (kg)|المستهلك', num: 1}, {k: 'bal', l: 'Balance (kg)|الرصيد', num: 1, f: x => `<b style="color:${(x ?? 0) < 20 ? 'var(--danger)' : 'inherit'}">${fmt(x)}</b>`},
      {k: 'drum', l: 'Drum left %|المتبقي من البرميل %', num: 1, d: 0}, {k: 'kpd', l: 'kg / day|كجم/يوم', num: 1}, {k: 'cover', l: 'Days of cover|يكفي (يوم)', num: 1, d: 0},
      {k: 'fc', l: 'Forecast (kg)|المتوقع', num: 1}], data, {file: 'grease-summary', title: L('Per plant|لكل محطة')});
  } else if (greaseView === 'daily') {
    const rows = tab('يومية');
    const alert = n((rows.find(r => String(r[0] || '').startsWith('حد تنبيه')) || [])[1]) || 20;
    const hi = hdr(rows, 'التاريخ');
    const items = rows.slice(hi + 1).filter(r => /^\d{4}-\d{2}-\d{2}/.test(String(r[0] || '')))
      .map(r => ({d: String(r[0]).slice(0, 10), p: plant(r[1]), t: r[2] === '' || r[2] === undefined ? null : n(r[2]), inn: n(r[3]), open: n(r[4]), use: n(r[5]), close: n(r[6]), cover: n(r[7])}));
    const missing = items.filter(x => x.t === null && x.d <= S.meta.to && items.some(y => y.d === x.d && y.t !== null));
    if (missing.length) {
      const by = {}; missing.forEach(x => (by[x.p] = by[x.p] || []).push(x.d.slice(8) + '/' + x.d.slice(5, 7)));
      panel(v).innerHTML = `<div class="warnbox" style="margin:0">⚠️ ${L('No trucks entered (so no balance) for|مفيش عربيات متسجلة (فمفيش رصيد) في')}: ${Object.entries(by).map(([pl, ds]) => `<b>${esc(pl)}</b> (${ds.length}: ${ds.slice(0, 6).join(', ')}${ds.length > 6 ? '…' : ''})`).join(' · ')}.
        ${L('Type the trucks, or 0 if the plant did not work.|اكتب عدد العربيات أو 0 لو المحطة ما اشتغلتش.')}</div>`;
    }
    table(v, [{k: 'd', l: 'Date|التاريخ', f: x => egDay(x)}, {k: 'p', l: 'Plant|المحطة'}, {k: 't', l: 'Trucks loaded|العربيات', num: 1, d: 0, sum: 1}, {k: 'inn', l: 'Received (kg)|الوارد', num: 1, sum: 1},
      {k: 'open', l: 'Opening (kg)|أول اليوم', num: 1}, {k: 'use', l: 'Used (kg)|المستهلك', num: 1, sum: 1},
      {k: 'close', l: 'Closing (kg)|آخر اليوم', num: 1, f: x => x === null ? '<span style="color:var(--ink3)">—</span>' : `<span style="${x < alert ? 'color:var(--danger);font-weight:700' : ''}">${fmt(x)}</span>`},
      {k: 'cover', l: 'Days of cover|يكفي (يوم)', num: 1, d: 0}], items.filter(x => x.d <= S.meta.to).reverse(), {file: 'grease-daily', title: `${L('Balance alert below|تنبيه لو الرصيد أقل من')} ${fmt(alert, 0)} kg`});
  } else {
    const rows = tab('رصيد أول'), hi = hdr(rows, 'الشهر');
    const head = hi >= 0 ? rows[hi] : [];
    const data = hi >= 0 ? rows.slice(hi + 1).filter(r => r.slice(1).some(x => x !== '' && x !== undefined)).map(r => { const o = {m: String(r[0]).slice(0, 7)}; head.forEach((h, i) => i && (o['c' + i] = n(r[i]))); return o; }) : [];
    table(v, [{k: 'm', l: 'Month|الشهر'}, ...head.slice(1).map((h, i) => ({k: 'c' + (i + 1), l: plant(h), num: 1}))], data, {file: 'grease-opening'});
  }
  panel(v).innerHTML = `<div class="tbar" style="margin:0"><span class="note">${L('From "استهلاك الشحم.xlsm" on Google Drive · updated every 5 minutes|من ملف "استهلاك الشحم.xlsm" على Google Drive · بيتحدث كل 5 دقايق')}</span><span class="grow"></span>
    <a class="btn sm" target="_blank" rel="noopener" href="${esc(d._edit_grease || '#')}">${L('Open the grease file ↗|افتح ملف الشحم ↗')}</a></div>`;
}

/* ---------- Google Sheets screens ---------- */
const sheetTab = {};
function rSheet(sec) {
  const v = $('view'), d = S.data[sec];
  const names = Object.keys(d).filter(k => !k.startsWith('_') && !k.startsWith('Grease'));
  if (Object.keys(d).some(k => k.startsWith('Grease'))) names.push('🛢️ Grease');       // one tab with the grease dashboard
  const t = sheetTab[sec] = names.includes(sheetTab[sec]) ? sheetTab[sec] : names[0];
  const p = panel(v);
  p.innerHTML = `<div class="tbar" style="margin:0"><div class="tabs" style="margin:0">${names.map(n => `<button data-k="${esc(n)}" class="${n === t ? 'on' : ''}">${esc(n)}</button>`).join('')}</div><span class="grow"></span>
    <a class="btn sm" target="_blank" rel="noopener" href="${esc(t.startsWith('Grease') && d._edit_grease ? d._edit_grease : d._edit)}">${L('Open the sheet ↗|افتح الشيت ↗')}</a></div>`;
  p.onclick = e => { if (e.target.dataset.k) { sheetTab[sec] = e.target.dataset.k; show(cur, true); } };
  if (t === '🛢️ Grease') { p.querySelector('a.btn').remove(); return rGrease(v, d); }
  const raw = (d[t] || []).filter(r => r.some(c => String(c).trim()));
  if (!raw.length) { panel(v).innerHTML = `<div class="empty">${L('This tab is empty|التاب ده فاضي')}</div>`; return; }
  const hi = raw.findIndex(r => r.filter(c => String(c).trim()).length >= Math.min(3, Math.max(...raw.map(x => x.filter(c => String(c).trim()).length))));
  const head = raw[hi].map((h, i) => String(h).trim() || '#' + (i + 1));
  const width = Math.max(...raw.map(r => r.length));
  const used = [...Array(width).keys()].filter(i => raw.slice(hi).some(r => String(r[i] ?? '').trim()));
  const isNum = i => raw.slice(hi + 1).filter(r => String(r[i] ?? '').trim()).every(r => /^-?[\d,]+(\.\d+)?%?$/.test(String(r[i]).trim()));
  const cols = used.map(i => ({k: 'c' + i, l: head[i] || '#' + (i + 1), num: isNum(i), f: isNum(i) ? x => esc(x) : null}));
  const data = raw.slice(hi + 1).map(r => { const o = {}; used.forEach(i => o['c' + i] = r[i] ?? ''); return o; });
  table(v, cols, data, {file: sec + '-' + t});
}

/* ---------- outside pages (Pour Tracker, Ice Calculate) inside the content area ---------- */
function rFrame(v, url) {                            // a whole page in the content area
  const p = panel(v); p.style.padding = '0'; p.style.overflow = 'hidden';
  p.innerHTML = `<iframe src="${esc(url)}" title="${esc(L(SCREENS.find(s => s.id === cur).t))}" style="width:100%;height:calc(100vh - 170px);min-height:600px;border:0;display:block;background:#fff"></iframe>`;
  return p.querySelector('iframe');
}

/* ---------- monitor: the same glowing network page as the NCM Hub, fed with the snapshot ---------- */
function rMonitor(v) {
  window.HUB = {monitor: S.data.monitor};             // monitor.html reads parent.HUB.monitor
  const p = panel(v); p.style.padding = '0'; p.style.overflow = 'hidden';
  p.innerHTML = '<iframe id="monF" src="monitor.html?v=3" title="Monitor" style="width:100%;height:1250px;border:0;display:block;background:transparent"></iframe>';
  const f = p.querySelector('iframe');
  f.onload = () => {
    try {
      const d = f.contentDocument, th = document.documentElement.dataset.theme;
      if (th) d.documentElement.dataset.theme = th;
      const fit = () => { f.style.height = Math.max(700, d.documentElement.scrollHeight) + 'px'; };
      fit(); setTimeout(fit, 800);
    } catch (e) {}
  };
  if (S.ring.admin && (S.data.monitor.export_problems || []).length) panel(v, L('Export warnings|تحذيرات التصدير')).innerHTML += `<ul class="act">${S.data.monitor.export_problems.map(x => `<li><div><small>${esc(x)}</small></div></li>`).join('')}</ul>`;
}
/* ------------------------------------------------------------------ admin: users */
const PERMS = [['prod', 'Production (dashboard, deliveries, customers, returned, trucks)|الإنتاج (الرئيسية، الرحلات، العملاء، المرتجع، الخلاطات)'],
  ['mat', 'Materials (consumption, target vs actual, formula control)|المواد (الاستهلاك، المستهدف والفعلي، مراجعة الخلطات)'], ['mix', 'Mix Designs|تصميمات الخلطات'],
  ['cons', 'Consumption (Mix Theory vs Dry)|الاستهلاك (النظري والفعلي)'], ['cement', 'Cement|الأسمنت'], ['manpower', 'Manpower|المانباور'], ['maint', 'Maintenance|الصيانة'], ['monitor', 'Monitor|المونيتور'], ['hub', 'Pour Tracker & Ice Calculate|متابعة الصبات وحساب التلج']];
const GH = {token: '', sha: '', users: null};
async function ghToken() {
  if (GH.token) return GH.token;
  try { const box = JSON.parse(localStorage.getItem('ncmGh:' + S.uid) || 'null'); if (box) GH.token = dec.decode(await open(S.k, box)); } catch (e) {}
  return GH.token;
}
async function gh(path, opt = {}) {
  const r = await fetch('https://api.github.com/repos/' + REPO + path, {...opt, cache: 'no-store',
    headers: {Accept: 'application/vnd.github+json', Authorization: 'Bearer ' + await ghToken(), ...(opt.headers || {})}});
  if (!r.ok) throw new Error('GitHub ' + r.status + ({
    401: ' — ' + L('the GitHub key is wrong or expired|مفتاح GitHub غلط أو انتهى'),
    403: ' — ' + L('the GitHub key can read but not save: on github.com/settings/personal-access-tokens edit it and set Contents to "Read and write"|مفتاح GitHub بيقرا بس ومش بيحفظ: من github.com/settings/personal-access-tokens عدّله وخلي Contents على "Read and write"')}[r.status] || ''));
  return r.json();
}
async function loadUsers() {
  const f = await gh('/contents/users.json?ref=main');
  GH.sha = f.sha; GH.users = JSON.parse(dec.decode(ub64(f.content.replace(/\n/g, ''))));
}
async function saveUsers(msg) {
  const body = enc.encode(JSON.stringify(GH.users, null, 1));
  const f = await gh('/contents/users.json', {method: 'PUT', body: JSON.stringify({message: msg, content: b64(body), sha: GH.sha, branch: 'main'})});
  GH.sha = f.content.sha;
}
const pending = {};                                  // names of users added in this session (the server lists them within 5 min)
let admTab = 'users';

/* Admin > Settings: the program's plant connections (read-only: they are changed in the program's
   Settings, the site follows within 5 minutes) and which screens the users see (settings.json). */
function rSettings(v) {
  const cfg = S.ring.plants_cfg || [];
  const pp = panel(v, '🏭 ' + L('Plants (network connections)|المحطات (اتصالات الشبكة)'));
  pp.innerHTML += `<div class="tw"><table><thead><tr><th>${L('Label|الاسم')}</th><th>Host / IP</th><th>Port</th><th>DB path</th><th>${L('Status|الحالة')}</th></tr></thead><tbody>
    ${cfg.map(p => `<tr><td><b>${esc(p.label)}</b></td><td>${esc(p.host) || '—'}</td><td>${esc(p.port)}</td><td><small>${esc(p.path)}</small></td>
      <td><span class="pill ${p.up ? 'ok' : 'off'}">${p.up ? L('Answering|شغالة') : L('Not reachable|مش متاحة')}</span></td></tr>`).join('') || `<tr><td colspan="5" class="empty">${L('Shown after the next data update (5 min)|بيظهر بعد التحديث الجاي (5 دقايق)')}</td></tr>`}</tbody></table></div>
    <p class="note">${L('To add a plant or change an IP, use Settings in the NCM PLANTS program on the office network; the site follows it within 5 minutes. It is not editable from the internet on purpose: these connections reach the plant databases.|لإضافة محطة أو تغيير IP استخدم الإعدادات في برنامج NCM PLANTS على شبكة المكتب؛ الموقع بيتبعه خلال 5 دقايق. مقفولة من الإنترنت عن قصد لأنها بتوصل لقواعد بيانات المحطات.')}</p>`;

  const shown = SCREENS.filter(s => !s.admin);
  const sp = panel(v, '👁️ ' + L('Visible screens|الشاشات الظاهرة'));
  sp.innerHTML += `<p class="note" style="margin-top:0">${L('Untick a screen to remove it from the menu for everyone, you included; tick it again here to bring it back. Per-person access is set in Users.|شيل العلامة علشان الشاشة تختفي من القائمة عند الكل وانت كمان؛ علّم عليها تاني هنا علشان ترجع. صلاحية كل شخص بتتظبط من المستخدمين.')}</p>
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:8px">${shown.map(s => `<label style="display:flex;gap:10px;align-items:center;padding:8px 10px;border-radius:10px;background:var(--card2);cursor:pointer">
      <input type="checkbox" data-s="${s.id}" style="width:auto" ${hidden(s) ? '' : 'checked'}><svg class="i"><use href="#i-${s.ic}"/></svg>${L(s.t)}</label>`).join('')}</div>
    <div class="tbar" style="margin:14px 0 0"><span class="err" id="sE"></span><span class="grow"></span><button class="btn primary" id="sSave">${L('Save|حفظ')}</button></div>`;
  $('sSave').onclick = async () => {
    const hid = [...sp.querySelectorAll('[data-s]')].filter(c => !c.checked).map(c => c.dataset.s);
    $('sE').textContent = ''; $('sSave').disabled = true;
    try {
      let sha; try { sha = (await gh('/contents/settings.json?ref=main')).sha; } catch (e) { if (!/404/.test(e.message)) throw e; }
      const body = {...(S.settings || {}), hidden: hid};
      await gh('/contents/settings.json', {method: 'PUT', body: JSON.stringify({message: 'settings: visible screens', branch: 'main', ...(sha ? {sha} : {}),
        content: b64(enc.encode(JSON.stringify(body, null, 1)))})});
      S.settings = body; buildNav(); show('users', true); toast(L('Saved ✓ — users see it within 5 minutes|اتحفظ ✓ — بيوصل للمستخدمين خلال 5 دقايق'));
    } catch (e) { $('sE').textContent = e.message; } finally { $('sSave').disabled = false; }
  };
}

async function rUsers(v) {
  if (!await ghToken()) {
    panel(v, L('Connect the admin page to GitHub (one time)|اربط صفحة الأدمن بـ GitHub (مرة واحدة)')).innerHTML += `
      <div class="warnbox">${L('Saving users needs a GitHub key that can edit only this site. It is kept encrypted with your password on this device.|حفظ المستخدمين محتاج مفتاح GitHub يقدر يعدّل الموقع ده بس. بيتحفظ متشفّر بكلمة السر بتاعتك على الجهاز ده.')}</div>
      <ol class="note" style="line-height:1.9">
        <li>${L('Open|افتح')} <a href="https://github.com/settings/personal-access-tokens/new" target="_blank" rel="noopener">github.com/settings/personal-access-tokens/new</a></li>
        <li>${L('Name: NCM site admin · Expiration: 1 year|الاسم: NCM site admin · المدة: سنة')}</li>
        <li>${L('Repository access: Only select repositories → ncm-plants|Repository access: Only select repositories ← ncm-plants')}</li>
        <li>${L('Permissions → Repository → Contents: Read and write|Permissions ← Repository ← Contents: Read and write')}</li>
        <li>${L('Generate token, copy it and paste it here|اضغط Generate token وانسخه وحطه هنا')}</li></ol>
      <div class="tbar"><input type="password" id="ghT" placeholder="github_pat_…" style="flex:1"><button class="btn primary" id="ghS">${L('Save|حفظ')}</button></div><div class="err" id="ghE"></div>`;
    $('ghS').onclick = async () => {
      GH.token = $('ghT').value.trim(); $('ghE').textContent = '';
      try { await loadUsers(); localStorage.setItem('ncmGh:' + S.uid, JSON.stringify(await sealBytes(S.k, enc.encode(GH.token)))); toast(L('Connected ✓|اتربط ✓')); show('users', true); }
      catch (e) { GH.token = ''; $('ghE').textContent = e.message; }
    };
    return;
  }
  const tb = panel(v);
  tb.innerHTML = `<div class="tabs" style="margin:0">${[['users', '👤 Users|👤 المستخدمين'], ['settings', '⚙️ Settings|⚙️ الإعدادات']].map(([k, t]) => `<button data-k="${k}" class="${admTab === k ? 'on' : ''}">${L(t)}</button>`).join('')}</div>`;
  tb.onclick = e => { if (e.target.dataset.k) { admTab = e.target.dataset.k; show('users', true); } };
  if (admTab === 'settings') return rSettings(v);
  const p = panel(v); p.innerHTML = '<div class="spin"></div>';
  try { await loadUsers(); } catch (e) { p.innerHTML = `<div class="err">${esc(e.message)}</div><button class="btn" onclick="localStorage.removeItem('ncmGh:'+S.uid);GH.token='';show('users')">${L('Enter a new GitHub key|حط مفتاح GitHub جديد')}</button>`; return; }
  const dir = Object.fromEntries((S.ring.directory || []).map(d => [d.uid, d]));
  const list = GH.users.users.map(u => ({...u, ...(dir[u.uid] ? {user: dir[u.uid].user, name: dir[u.uid].name} : pending[u.uid] || {user: '?', name: L('(new — ready within 5 min)|(جديد — بيجهز خلال 5 دقايق)')})}));
  const plants = S.meta.plants;
  p.innerHTML = `<h3><span>${L('Users and permissions|المستخدمين والصلاحيات')}</span><span class="tag">${list.length}</span></h3>
    <div class="tbar"><button class="btn primary" id="uAdd">+ ${L('Add a user|إضافة مستخدم')}</button><span class="grow"></span>
    <span class="note">${L('Changes reach the site within 5 minutes.|التعديلات بتوصل للموقع خلال 5 دقايق.')}</span>
    <button class="btn sm" onclick="localStorage.removeItem('ncmGh:'+S.uid);GH.token='';show('users')">${L('Change GitHub key|غيّر مفتاح GitHub')}</button></div>
    <div class="tw"><table><thead><tr><th>${L('Person|الشخص')}</th><th>${L('Status|الحالة')}</th><th>${L('Screens|الشاشات')}</th><th>${L('Plants|المحطات')}</th><th></th></tr></thead><tbody>
    ${list.map(u => `<tr><td><b>${esc(u.name)}</b>${u.admin ? ' <span class="pill ok">Admin</span>' : ''}<small style="display:block;color:var(--ink3)">${esc(u.user)}</small></td>
      <td><span class="pill ${u.disabled ? 'off' : 'ok'}">${u.disabled ? L('Stopped|موقوف') : L('Active|مفعّل')}</span></td>
      <td>${u.admin ? L('Everything|كل حاجة') : `<div class="chips">${PERMS.filter(([k]) => (u.sections || []).includes(k)).map(([, t]) => `<span class="chip on">${esc(L(t).split(' (')[0])}</span>`).join('') || '—'}</div>`}</td>
      <td>${u.admin ? L('All|الكل') : `<div class="chips">${plants.filter(x => (u.plants || []).includes(x.id)).map(x => `<span class="chip on">${esc(x.label)}</span>`).join('') || '—'}</div>`}</td>
      <td style="white-space:nowrap">${u.uid === S.uid ? '' : `<button class="btn sm" data-e="${u.uid}">${L('Edit|تعديل')}</button>`}</td></tr>`).join('')}</tbody></table></div>`;
  $('uAdd').onclick = () => editUser(null);
  p.querySelectorAll('[data-e]').forEach(b => b.onclick = () => editUser(list.find(u => u.uid === b.dataset.e)));
}

function genPw() { const a = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'; return [...crypto.getRandomValues(new Uint32Array(10))].map(x => a[x % a.length]).join(''); }
async function newRecord(user, name, pw) {
  const k = crypto.getRandomValues(new Uint8Array(32)), salt = crypto.getRandomValues(new Uint8Array(16)), iter = 200000;
  const pem = S.meta.pub.replace(/-----[^-]+-----|\s/g, '');
  const pub = await crypto.subtle.importKey('spki', ub64(pem), {name: 'RSA-OAEP', hash: 'SHA-256'}, false, ['encrypt']);
  const srv = await crypto.subtle.encrypt({name: 'RSA-OAEP'}, pub, enc.encode(JSON.stringify({k: b64(k), u: user, n: name})));
  return {uid: await sha256hex(user), salt: b64(salt), iter, pw_box: await sealBytes(await pwKey(pw, salt, iter), k), srv_box: b64(srv)};
}
function editUser(u) {
  const isNew = !u; u = u || {sections: ['prod'], plants: S.meta.plants.map(p => p.id)};
  const m = $('modal'), b = $('mbox');
  b.innerHTML = `<h3>${isNew ? L('Add a user|إضافة مستخدم') : L('Edit|تعديل') + ' — ' + esc(u.name)}</h3>
    ${isNew ? `<div class="row2"><div class="fld"><label>${L('Username (to sign in)|اسم المستخدم (للدخول)')}</label><input id="eU" maxlength="30" autocapitalize="none" spellcheck="false"></div>
      <div class="fld"><label>${L('Name shown|الاسم اللي يظهر')}</label><input id="eN" maxlength="40"></div></div>` : ''}
    <div class="fld"><label>${isNew ? L('Password|كلمة السر') : L('New password (leave empty to keep the old one)|كلمة سر جديدة (سيبها فاضية علشان تفضل القديمة)')}</label>
      <div class="tbar" style="margin:0"><input id="eP" style="flex:1" autocomplete="new-password"><button class="btn sm" id="eG" type="button">${L('Generate|اقترح')}</button></div>
      <span class="note">${L('At least 8 characters. Send it to the person yourself; the site never shows it again.|8 حروف على الأقل. ابعتها للشخص بنفسك؛ الموقع مش هيعرضها تاني.')}</span></div>
    <div class="fld"><label><input type="checkbox" id="eA" style="width:auto" ${u.admin ? 'checked' : ''}> ${L('Admin (sees everything and manages users)|أدمن (يشوف كل حاجة ويدير المستخدمين)')}</label></div>
    <div id="ePerm"><div class="fld"><label>${L('Screens|الشاشات')}</label><div class="chips" id="eS">${PERMS.map(([k, t]) => `<span class="chip ${u.sections?.includes(k) ? 'on' : ''}" data-k="${k}">${esc(L(t))}</span>`).join('')}</div></div>
    <div class="fld"><label>${L('Plants (for production, materials and mix designs)|المحطات (للإنتاج والمواد والخلطات)')}</label><div class="chips" id="ePl">${S.meta.plants.map(p => `<span class="chip ${u.plants?.includes(p.id) ? 'on' : ''}" data-k="${p.id}">${esc(p.label)}</span>`).join('')}</div></div></div>
    <div class="err" id="eE"></div>
    <div class="tbar" style="margin:14px 0 0">${isNew ? '' : `<button class="btn sm" id="eD" style="color:var(--danger)">${L('Delete|حذف')}</button><button class="btn sm" id="eX">${u.disabled ? L('Activate|تفعيل') : L('Stop|إيقاف')}</button>`}
      <span class="grow"></span><button class="btn" id="eC">${L('Cancel|إلغاء')}</button><button class="btn primary" id="eOk">${L('Save|حفظ')}</button></div>`;
  m.classList.add('on');
  const perm = () => $('ePerm').style.opacity = $('eA').checked ? .4 : 1; perm(); $('eA').onchange = perm;
  ['eS', 'ePl'].forEach(id => $(id).onclick = e => e.target.dataset.k && e.target.classList.toggle('on'));
  $('eG').onclick = () => { $('eP').value = genPw(); };
  $('eC').onclick = () => m.classList.remove('on');
  const picked = id => [...$(id).querySelectorAll('.chip.on')].map(c => c.dataset.k);
  const commit = async (fn, msg) => {
    $('eE').textContent = ''; $('eOk').disabled = true;
    try { await loadUsers(); await fn(GH.users.users); await saveUsers(msg); m.classList.remove('on'); toast(L('Saved ✓ — active within 5 minutes|اتحفظ ✓ — بيتفعّل خلال 5 دقايق')); show('users', true); }
    catch (e) { $('eE').textContent = e.message; } finally { $('eOk').disabled = false; }
  };
  if (!isNew) {
    $('eD').onclick = () => confirm(L('Delete this user?|تحذف المستخدم ده؟')) && commit(us => { GH.users.users = us.filter(x => x.uid !== u.uid); }, 'users: delete');
    $('eX').onclick = () => commit(us => { us.find(x => x.uid === u.uid).disabled = !u.disabled; }, 'users: ' + (u.disabled ? 'activate' : 'stop'));
  }
  $('eOk').onclick = () => {
    const pw = $('eP').value, admin = $('eA').checked, sections = picked('eS'), plants = picked('ePl');
    if ((isNew || pw) && pw.length < 8) { $('eE').textContent = L('The password must be at least 8 characters|كلمة السر لازم 8 حروف على الأقل'); return; }
    if (isNew) {
      const user = $('eU').value.trim().toLowerCase(), name = $('eN').value.trim() || user;
      if (!/^[a-z0-9._-]{3,30}$/.test(user)) { $('eE').textContent = L('Username: 3-30 English letters, numbers or . _ -|اسم المستخدم: 3-30 حرف إنجليزي أو أرقام أو . _ -'); return; }
      commit(async us => {
        const rec = await newRecord(user, name, pw);
        if (us.some(x => x.uid === rec.uid)) throw new Error(L('This username already exists|اسم المستخدم ده موجود'));
        pending[rec.uid] = {user, name: name + ' ' + L('(ready within 5 min)|(بيجهز خلال 5 دقايق)')};
        us.push({...rec, admin, sections, plants});
      }, 'users: add');
    } else {
      commit(async us => {
        const x = us.find(y => y.uid === u.uid); Object.assign(x, {admin, sections, plants});
        if (pw) Object.assign(x, await newRecord(u.user, u.name, pw), {uid: x.uid});     // same account, new password
      }, 'users: edit');
    }
  };
}

/* ------------------------------------------------------------------ boot */
applyLang();
(async () => {
  try {
    const s = JSON.parse(sessionStorage.ncmS || 'null');
    if (s) { S.uid = s.uid; S.kRaw = ub64(s.k); S.k = await aesKey(S.kRaw); await start(); }
  } catch (e) { $('lerr').textContent = e.message; try { sessionStorage.removeItem('ncmS'); } catch (x) {} }
})();
