const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const url = require('url');

const CONFIG = {
  recruiterflow: { apiKey: process.env.RECRUITERFLOW_API_KEY },
  msGraph: {
    tenantId: process.env.MS_TENANT_ID,
    clientId: process.env.MS_CLIENT_ID,
    clientSecret: process.env.MS_CLIENT_SECRET
  },
  zoom: {
    accountId: process.env.ZOOM_ACCOUNT_ID,
    clientId: process.env.ZOOM_CLIENT_ID,
    clientSecret: process.env.ZOOM_CLIENT_SECRET
  },
  ringcentral: {
    clientId: process.env.RC_CLIENT_ID_NEW || process.env.RC_CLIENT_ID,
    clientSecret: process.env.RC_CLIENT_SECRET_NEW || process.env.RC_CLIENT_SECRET
  }
};

const tokens = { ms: null, zoom: null, rc: null, msExpiry: null };
const callsCache = { data: null, expiry: 0 };
const candidatesCache = { data: null, expiry: 0, ids: null, lastFull: 0 };
const contactsCache = { data: null, expiry: 0 };

// ── Manual label overrides ─────────────────────────────────
// Lets Shane correct a mislabeled person (e.g. someone the system defaulted to
// "Contact" who's actually an insurance producer) directly from the dashboard.
// Saved to disk so it survives refreshes and both users see the same label.
// This is deliberately just a DISPLAY label — classifyMeeting() always checks
// real RecruiterFlow data first, so the moment a genuine Candidate or Contact
// record appears for that name, the real data takes over automatically and
// this override simply stops being consulted for that person.
const OVERRIDES_FILE = path.join(__dirname, 'overrides.json');

function loadOverrides() {
  try {
    return JSON.parse(fs.readFileSync(OVERRIDES_FILE, 'utf8'));
  } catch(e) {
    return {}; // file doesn't exist yet, or is invalid — start fresh
  }
}

function saveOverrides(overrides) {
  fs.writeFileSync(OVERRIDES_FILE, JSON.stringify(overrides, null, 2));
}

// ── Candidate notes, written from the dashboard ────────────────────────────
// Notes are stored in BOTH places, and the local copy is the one the dashboard
// reads back. That is not belt-and-braces, it is necessary: RecruiterFlow's
// candidate/list endpoint does not return a `notes` field at all, so a note
// pushed only to RecruiterFlow would vanish from this dashboard on the next
// refresh — you would type it and watch it disappear.
//
// The RecruiterFlow push is therefore best-effort and its result is reported
// back to the UI rather than swallowed, so a failure to reach the CRM is
// visible instead of being mistaken for a successful save.
const NOTES_FILE = path.join(__dirname, 'notes.json');

function loadNotes() {
  try {
    return JSON.parse(fs.readFileSync(NOTES_FILE, 'utf8'));
  } catch (e) {
    return {}; // not written yet, or unreadable — start fresh
  }
}

function saveNotes(notes) {
  // Write to a temp file and rename, so an interrupted write can't leave a
  // truncated notes.json behind and lose everything he has typed.
  const tmp = NOTES_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(notes, null, 2));
  fs.renameSync(tmp, NOTES_FILE);
}

async function pushNoteToRecruiterFlow(id, text) {
  if (!id) return { attempted: false, reason: 'no RecruiterFlow id on this record' };
  if (!CONFIG.recruiterflow.apiKey) return { attempted: false, reason: 'no API key configured' };
  const payload = JSON.stringify({ id: Number(id) || id, notes: [text] });
  try {
    const res = await fetchJSON({
      hostname: 'recruiterflow.com',
      path: '/api/external/candidate/update',
      method: 'POST',
      headers: {
        'rf-api-key': CONFIG.recruiterflow.apiKey,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload)
      }
    }, payload);
    return { attempted: true, ok: res.status >= 200 && res.status < 300, status: res.status, body: res.body };
  } catch (e) {
    return { attempted: true, ok: false, error: e.message };
  }
}

function fetchJSON(options, body) {
  return new Promise((resolve, reject) => {
    const req = https.request(options, res => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
        catch(e) { resolve({ status: res.statusCode, body: data }); }
      });
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

function encodeForm(obj) {
  return Object.entries(obj).map(([k,v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&');
}

async function getMSToken() {
  // Clear cached token if expired (50 min expiry)
  if (tokens.msExpiry && Date.now() > tokens.msExpiry) {
    tokens.ms = null;
    tokens.msExpiry = null;
  }
  if (tokens.ms) return tokens.ms;
  const body = encodeForm({
    grant_type: 'client_credentials',
    client_id: CONFIG.msGraph.clientId,
    client_secret: CONFIG.msGraph.clientSecret,
    scope: 'https://graph.microsoft.com/.default'
  });
  const res = await fetchJSON({
    hostname: 'login.microsoftonline.com',
    path: `/${CONFIG.msGraph.tenantId}/oauth2/v2.0/token`,
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) }
  }, body);
  if (res.body.access_token) {
    tokens.ms = res.body.access_token;
    tokens.msExpiry = Date.now() + (50 * 60 * 1000); // 50 minutes
    console.log('MS token acquired successfully');
  } else {
    console.error('MS token error:', JSON.stringify(res.body));
  }
  return tokens.ms;
}

// Zoom server-to-server tokens expire after an hour. This used to cache the
// token forever — `if (tokens.zoom) return tokens.zoom` with nothing to expire
// it — so every Zoom call failed permanently one hour after a deploy until the
// process happened to restart. It also meant a scope added in the Zoom
// Marketplace never took effect on a running instance, because the old
// scope-less token was still being handed out.
async function getZoomToken() {
  if (tokens.zoom && tokens.zoomExpiry && Date.now() < tokens.zoomExpiry) {
    return tokens.zoom;
  }
  const creds = Buffer.from(`${CONFIG.zoom.clientId}:${CONFIG.zoom.clientSecret}`).toString('base64');
  const res = await fetchJSON({
    hostname: 'zoom.us',
    path: `/oauth/token?grant_type=account_credentials&account_id=${CONFIG.zoom.accountId}`,
    method: 'POST',
    headers: { 'Authorization': `Basic ${creds}`, 'Content-Length': 0 }
  }, '');
  if (!res.body?.access_token) {
    throw new Error(`Zoom token request failed: ${res.status} ${JSON.stringify(res.body).slice(0, 200)}`);
  }
  tokens.zoom = res.body.access_token;
  // Refresh a minute early rather than racing the expiry.
  const ttl = Number(res.body.expires_in || 3600);
  tokens.zoomExpiry = Date.now() + Math.max(60, ttl - 60) * 1000;
  return tokens.zoom;
}

// Discards the cached token so the next call re-authenticates. Used after a
// scope change, so a new scope can be picked up without redeploying.
function resetZoomToken() {
  tokens.zoom = null;
  tokens.zoomExpiry = null;
}

async function zoomGet(path) {
  const token = await getZoomToken();
  const res = await fetchJSON({
    hostname: 'api.zoom.us', path, method: 'GET',
    headers: { 'Authorization': `Bearer ${token}` }
  });
  return res;
}

// Zoom meeting UUIDs are base64 and can contain '/' or begin with one. Those
// must be double URL-encoded or the path breaks. This is the single most common
// way Zoom meeting lookups fail, so it lives in one place.
function encodeMeetingUuid(uuid) {
  const once = encodeURIComponent(uuid);
  return (uuid.startsWith('/') || uuid.includes('//')) ? encodeURIComponent(once) : once;
}

async function getRCToken() {
  if (tokens.rc && tokens.rcExpiry && Date.now() < tokens.rcExpiry) return tokens.rc;
  const creds = Buffer.from(`${process.env.RC_CLIENT_ID_NEW || process.env.RC_CLIENT_ID}:${process.env.RC_CLIENT_SECRET_NEW || process.env.RC_CLIENT_SECRET}`).toString('base64');
  const body = encodeForm({
    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    assertion: process.env.RC_JWT
  });
  const res = await fetchJSON({
    hostname: 'platform.ringcentral.com',
    path: '/restapi/oauth/token',
    method: 'POST',
    headers: {
      'Authorization': `Basic ${creds}`,
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': Buffer.byteLength(body)
    }
  }, body);
  if (res.body.access_token) {
    tokens.rc = res.body.access_token;
    tokens.rcExpiry = Date.now() + (50 * 60 * 1000);
    console.log('RC token acquired successfully');
  } else {
    console.error('RC token error:', JSON.stringify(res.body));
  }
  return tokens.rc;
  return tokens.rc;
}

// ── Candidate list: incremental sync ──────────────────────────────────────
// The old loader re-crawled the entire candidate list — 201 sequential
// RecruiterFlow calls, ~40 seconds — every time the 20-minute cache lapsed.
// It also capped at 200 pages (20,000 records) and the list had already
// reached 20,029, so the oldest candidates were silently invisible.
//
// The fix leans on a property of the API: /candidate/list returns records
// strictly newest-first (verified across 20,028 consecutive pairs, zero out
// of order). So a refresh only has to page until it meets a record it already
// holds, then stop. In practice that is a single call instead of 201.
//
// Two caveats, handled below. Sorting is by date added, so an EDIT to an
// existing candidate does not float it to the top and a top-up won't see it;
// a deletion won't be noticed either. Both are caught by forcing a full
// re-crawl once a day.
const RF_PAGE_SIZE = 100;
const RF_MAX_PAGES = 600;              // ceiling raised: the pool had already hit the old 200
// Overridable so the sync can be exercised without waiting out real timers.
const CAND_TTL = Number(process.env.CAND_TTL_MS || 20 * 60000);        // serve from memory
const CAND_FULL_TTL = Number(process.env.CAND_FULL_TTL_MS || 24 * 3600000); // full re-crawl interval
let candidatesInFlight = null;         // collapses concurrent requests into one fetch

async function fetchCandidatePage(page) {
  const res = await fetchJSON({
    hostname: 'recruiterflow.com',
    path: `/api/external/candidate/list?current_page=${page}&items_per_page=${RF_PAGE_SIZE}`,
    method: 'GET',
    headers: { 'rf-api-key': CONFIG.recruiterflow.apiKey }
  });
  return Array.isArray(res.body) ? res.body : (res.body?.data || []);
}

const candidateId = c => c.id ?? c.prospect_id ?? null;

// RecruiterFlow sometimes stuffs credentials or titles into last_name
// (e.g. "Soto M.A., Insurance Agent"). Same normalisation the client uses, kept
// here so server-side lookups and client-side matching can't drift apart.
function rfCleanLastName(s) {
  return (s || '').split(',')[0].replace(/\b([A-Z]\.){1,3}[A-Z]?\.?\b/g, '').trim();
}
function rfFullName(c) {
  return `${c.first_name || ''} ${rfCleanLastName(c.last_name)}`.trim();
}

function buildNameIndex(list) {
  const byFull = new Map(), byFirst = new Map();
  for (const c of list) {
    const full = rfFullName(c).toLowerCase();
    if (!full) continue;
    if (!byFull.has(full)) byFull.set(full, c);
    const first = full.split(' ')[0];
    if (!first) continue;
    if (!byFirst.has(first)) byFirst.set(first, []);
    byFirst.get(first).push(c);
  }
  return { byFull, byFirst };
}

function setCandidateCache(list, isFull) {
  const now = Date.now();
  candidatesCache.data = list;
  candidatesCache.ids = new Set(list.map(candidateId).filter(v => v !== null));
  candidatesCache.index = buildNameIndex(list);
  candidatesCache.expiry = now + CAND_TTL;
  if (isFull) candidatesCache.lastFull = now;
}

// ── Geocoding, from the baked gazetteer ───────────────────────────────────
// RecruiterFlow stores a city and a full state name but no coordinates. The
// gazetteer is read once into memory here and never sent to the browser — the
// client only needs coordinates for the handful of people on screen, which
// ride along on the lookup response for about 20 bytes each.
let GAZETTEER = null;
// Checked in both places so the file works whether it is committed under geo/
// or dropped at the repo root — GitHub's web uploader flattens directories, so
// insisting on one location would make this undeployable without a terminal.
const GAZETTEER_PATHS = [
  path.join(__dirname, 'geo', 'us-cities.json'),
  path.join(__dirname, 'us-cities.json')
];
function gazetteer() {
  if (GAZETTEER) return GAZETTEER;
  for (const p of GAZETTEER_PATHS) {
    try {
      GAZETTEER = JSON.parse(fs.readFileSync(p, 'utf8'));
      console.log(`[geo] gazetteer loaded from ${p} — ${Object.keys(GAZETTEER.cities).length} cities`);
      return GAZETTEER;
    } catch (e) { /* try the next location */ }
  }
  // The map degrades to "no location on file" rather than taking the page down.
  console.warn('[geo] gazetteer not found in', GAZETTEER_PATHS.join(' or '), '— map will be empty');
  GAZETTEER = { cities: {}, stateCentroids: {}, stateCodes: {} };
  return GAZETTEER;
}

// Returns coordinates plus how precise they are, so the map can distinguish a
// real city pin from a whole-state approximation instead of implying accuracy
// it doesn't have.
function geoForCandidate(c) {
  const L = (c.location && typeof c.location === 'object') ? c.location : {};
  const g = gazetteer();
  const raw = String(L.state || '').trim();
  const code = raw.length === 2 ? raw.toUpperCase() : (g.stateCodes[raw] || null);
  const city = String(L.city || '').trim();

  if (city && code) {
    const hit = g.cities[city.toLowerCase() + '|' + code];
    if (hit) return { lat: hit[0], lon: hit[1], city, state: code, precision: 'city' };
  }
  if (code && g.stateCentroids[code]) {
    const ct = g.stateCentroids[code];
    return { lat: ct[0], lon: ct[1], city, state: code, precision: 'state' };
  }
  return null;
}

// Resolve meeting attendee names to candidate records. Returns only the
// matches, keyed by the name asked for — the dashboard used to download all
// 20,000 records (29MB) to find the four it needed.
function lookupCandidates(names) {
  const idx = candidatesCache.index;
  const out = {};
  if (!idx) return out;

  for (const raw of names) {
    const q = (raw || '').trim();
    if (!q) continue;
    const lower = q.toLowerCase();

    let hit = idx.byFull.get(lower);
    if (!hit) {
      const parts = lower.split(/\s+/).filter(Boolean);
      const sameFirst = idx.byFirst.get(parts[0]) || [];
      if (parts.length === 1) {
        // Only accept a first-name-only match when it is unambiguous.
        if (sameFirst.length === 1) hit = sameFirst[0];
      } else {
        const last = parts[parts.length - 1];
        const narrowed = sameFirst.filter(c =>
          rfCleanLastName(c.last_name).toLowerCase().startsWith(last[0]));
        if (narrowed.length === 1) hit = narrowed[0];
        else if (sameFirst.length === 1) hit = sameFirst[0];
      }
    }
    if (hit) out[q] = { ...hit, _geo: geoForCandidate(hit) };
  }
  return out;
}

// Free-text search across the server-side pool, so he can find someone without
// switching to RecruiterFlow. Ranked: name matches beat company and title.
function searchCandidates(q, limit = 25) {
  const list = candidatesCache.data || [];
  const needle = String(q || '').trim().toLowerCase();
  if (needle.length < 2) return [];

  const scored = [];
  for (const c of list) {
    const name = rfFullName(c).toLowerCase();
    const org = String(c.current_organization || '').toLowerCase();
    const title = String(c.current_designation || '').toLowerCase();
    const city = String(c.location?.city || '').toLowerCase();

    let score = 0;
    if (name === needle) score = 100;
    else if (name.startsWith(needle)) score = 80;
    else if (name.includes(needle)) score = 60;
    else if (org.includes(needle)) score = 40;
    else if (title.includes(needle)) score = 25;
    else if (city.includes(needle)) score = 15;
    if (!score) continue;

    // Nudge anyone with real recent activity above the bulk-imported pool.
    if (c.last_contacted) score += 6;
    scored.push({ score, c });
    if (scored.length > 4000) break;   // plenty to rank from; keeps this bounded
  }

  scored.sort((a, b) => b.score - a.score ||
    String(b.c.latest_activity_time || '').localeCompare(String(a.c.latest_activity_time || '')));
  return scored.slice(0, limit).map(s => s.c);
}

async function crawlAllCandidates() {
  let all = [];
  let page = 1;
  while (page <= RF_MAX_PAGES) {
    const pageData = await fetchCandidatePage(page);
    if (!pageData.length) break;
    all = all.concat(pageData);
    if (pageData.length < RF_PAGE_SIZE) break;
    page++;
  }
  if (page > RF_MAX_PAGES) {
    console.warn(`[candidates] hit the ${RF_MAX_PAGES}-page ceiling (${all.length} records). ` +
                 `Some candidates are NOT loaded — raise RF_MAX_PAGES.`);
  }
  return all;
}

// Pages from the top and stops at the first record already in cache.
async function topUpCandidates() {
  const known = candidatesCache.ids;
  const fresh = [];
  let page = 1;
  let reachedKnown = false;
  while (page <= RF_MAX_PAGES && !reachedKnown) {
    const pageData = await fetchCandidatePage(page);
    if (!pageData.length) break;
    for (const c of pageData) {
      const id = candidateId(c);
      if (id !== null && known.has(id)) { reachedKnown = true; break; }
      fresh.push(c);
    }
    if (reachedKnown || pageData.length < RF_PAGE_SIZE) break;
    page++;
  }
  return { fresh, pages: page, reachedKnown };
}

async function getCandidates() {
  if (candidatesInFlight) return candidatesInFlight;          // already fetching; join it

  const now = Date.now();
  if (candidatesCache.data && now < candidatesCache.expiry) return candidatesCache.data;

  candidatesInFlight = (async () => {
    const stale = !candidatesCache.data || (now - candidatesCache.lastFull) > CAND_FULL_TTL;
    if (stale) {
      const all = await crawlAllCandidates();
      setCandidateCache(all, true);
      console.log(`[candidates] full crawl — ${all.length} records`);
      return all;
    }

    const { fresh, pages, reachedKnown } = await topUpCandidates();
    // If we paged out without ever meeting a known record something is off
    // (a re-sort, or a very large gap); fall back to a full crawl rather than
    // quietly serving a list with a hole in it.
    if (!reachedKnown && fresh.length >= RF_PAGE_SIZE) {
      const all = await crawlAllCandidates();
      setCandidateCache(all, true);
      console.log(`[candidates] top-up overran, re-crawled — ${all.length} records`);
      return all;
    }

    const merged = fresh.length ? fresh.concat(candidatesCache.data) : candidatesCache.data;
    setCandidateCache(merged, false);
    console.log(`[candidates] top-up — +${fresh.length} new in ${pages} call(s), ${merged.length} total`);
    return merged;
  })();

  try {
    return await candidatesInFlight;
  } finally {
    candidatesInFlight = null;
  }
}

async function handleAPI(pathname, query) {

  // Debug single candidate detail
  if (pathname === '/api/debug/candidate') {
    const id = query.id || '31211';
    const res = await fetchJSON({
      hostname: 'recruiterflow.com',
      path: `/api/external/candidate/${id}`,
      method: 'GET',
      headers: { 'rf-api-key': CONFIG.recruiterflow.apiKey }
    });
    return { status: res.status, body: res.body };
  }

  // Debug: does a Contacts endpoint exist, following the same naming pattern as
  // /api/external/candidate/list? Read-only, completely safe to test.
  if (pathname === '/api/debug/contacts') {
    const res = await fetchJSON({
      hostname: 'recruiterflow.com',
      path: '/api/external/contact/list?current_page=1&items_per_page=5',
      method: 'GET',
      headers: { 'rf-api-key': CONFIG.recruiterflow.apiKey }
    });
    return { status: res.status, body: res.body };
  }

  // Debug: test creating a note directly via API. WRITES REAL DATA to Anthony Soto's
  // record (id 31211) if it succeeds — the note text is deliberately labeled as a test
  // so it's obvious and easy to delete afterward if this works.
  if (pathname === '/api/debug/create-note') {
    const payload = JSON.stringify({
      candidate_id: 31211,
      notes: '[TEST NOTE — dashboard API experiment, safe to delete] ' + new Date().toISOString()
    });
    const res = await fetchJSON({
      hostname: 'recruiterflow.com',
      path: '/api/external/notes/create',
      method: 'POST',
      headers: {
        'rf-api-key': CONFIG.recruiterflow.apiKey,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload)
      }
    }, payload);
    return { status: res.status, body: res.body };
  }

  // Debug: test the write-back endpoint with a safe, easily-reversible field first
  // (current_designation), before attempting anything stage/job-related. Anthony Soto
  // (id 31211) is no longer in an active process, so this is low-risk to test on.
  if (pathname === '/api/debug/update-candidate') {
    const payload = JSON.stringify({
      id: 31211,
      current_designation: 'Insurance Producer'
    });
    const res = await fetchJSON({
      hostname: 'recruiterflow.com',
      path: '/api/external/candidate/update',
      method: 'POST',
      headers: {
        'rf-api-key': CONFIG.recruiterflow.apiKey,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload)
      }
    }, payload);
    return { status: res.status, body: res.body };
  }

  // Debug: does candidate/update also let us write directly to the Notes field?
  // If so, this replaces the failed notes/create attempts and lets voice quick-notes
  // post straight to RecruiterFlow instead of requiring copy-paste.
  if (pathname === '/api/debug/update-notes') {
    const payload = JSON.stringify({
      id: 31211,
      notes: ['[TEST NOTE — dashboard API experiment, safe to delete] ' + new Date().toISOString()]
    });
    const res = await fetchJSON({
      hostname: 'recruiterflow.com',
      path: '/api/external/candidate/update',
      method: 'POST',
      headers: {
        'rf-api-key': CONFIG.recruiterflow.apiKey,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload)
      }
    }, payload);
    return { status: res.status, body: res.body };
  }

  // Debug: test a boolean field write — different data type than notes (array) or
  // current_designation (string). If this works, it opens the door to a real
  // "Do Not Contact" quick-toggle right on the candidate card.
  if (pathname === '/api/debug/update-donotemail') {
    const payload = JSON.stringify({
      id: 31211,
      do_not_email: true
    });
    const res = await fetchJSON({
      hostname: 'recruiterflow.com',
      path: '/api/external/candidate/update',
      method: 'POST',
      headers: {
        'rf-api-key': CONFIG.recruiterflow.apiKey,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload)
      }
    }, payload);
    return { status: res.status, body: res.body };
  }

  // Debug RC token
  if (pathname === '/api/debug/rctoken') {
    const clientId = process.env.RC_CLIENT_ID_NEW || process.env.RC_CLIENT_ID;
    const clientSecret = process.env.RC_CLIENT_SECRET_NEW || process.env.RC_CLIENT_SECRET;
    const jwt = process.env.RC_JWT || '';
    const creds = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
    const body = encodeForm({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: jwt
    });
    const res = await fetchJSON({
      hostname: 'platform.ringcentral.com',
      path: '/restapi/oauth/token',
      method: 'POST',
      headers: {
        'Authorization': `Basic ${creds}`,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body)
      }
    }, body);
    return {
      status: res.status,
      body: res.body,
      debug: {
        clientIdUsed: clientId,
        clientIdLength: clientId?.length,
        jwtLength: jwt.length,
        jwtStart: jwt.slice(0, 20),
        jwtEnd: jwt.slice(-20)
      }
    };
  }

  // Debug MS token
  if (pathname === '/api/calendar') {
    const token = await getMSToken();
    // Wide window covering full day in Central Time regardless of server UTC offset.
    // Central midnight-to-midnight spans into the NEXT UTC calendar day, so the end
    // boundary must roll over rather than stopping at the same UTC date's 23:59:59
    // (which was cutting off anything after ~7pm Central — the actual bug).
    const now = new Date();
    const centralOffset = 5 * 60 * 60 * 1000;
    const centralNow = new Date(now.getTime() - centralOffset);
    const today = centralNow.toISOString().split('T')[0];
    const centralNowPlus1 = new Date(centralNow.getTime() + 24*60*60*1000);
    const nextDay = centralNowPlus1.toISOString().split('T')[0];
    console.log('Fetching calendar for date:', today);
    const res = await fetchJSON({
      hostname: 'graph.microsoft.com',
      path: `/v1.0/users/${process.env.MS_USER_EMAIL}/calendarView?startDateTime=${today}T00:00:00Z&endDateTime=${nextDay}T04:59:59Z&$select=subject,start,end,bodyPreview,onlineMeeting,attendees&$orderby=start/dateTime&$top=20`,
      method: 'GET',
      headers: { 'Authorization': `Bearer ${token}` }
    });
    console.log('Calendar response status:', res.status, 'items:', res.body?.value?.length);
    return res.body;
  }

  if (pathname === '/api/calendar/tomorrow') {
    const token = await getMSToken();
    // Use Central Time (UTC-5) for tomorrow
    const now = new Date();
    const centralOffset = 5 * 60 * 60 * 1000;
    const centralNow = new Date(now.getTime() - centralOffset);
    centralNow.setDate(centralNow.getDate() + 1);
    const tDate = centralNow.toISOString().split('T')[0];
    const tDatePlus1 = new Date(centralNow.getTime() + 24*60*60*1000).toISOString().split('T')[0];
    const res = await fetchJSON({
      hostname: 'graph.microsoft.com',
      path: `/v1.0/users/${process.env.MS_USER_EMAIL}/calendarView?startDateTime=${tDate}T05:00:00Z&endDateTime=${tDatePlus1}T04:59:59Z&$select=subject,start,end,bodyPreview,onlineMeeting,attendees&$orderby=start/dateTime&$top=20`,
      method: 'GET',
      headers: { 'Authorization': `Bearer ${token}` }
    });
    return res.body;
  }

  if (pathname === '/api/emails') {
    const token = await getMSToken();
    const name = query.name || '';
    const email = query.email || '';

    if (email) {
      // Deterministic exact-match filter — reliable, unlike $search which Microsoft
      // documents as "eventually consistent" and can return different results moment to moment.
      const filter = `from/emailAddress/address eq '${email.replace(/'/g,"''")}' or toRecipients/any(r:r/emailAddress/address eq '${email.replace(/'/g,"''")}')`;
      const res = await fetchJSON({
        hostname: 'graph.microsoft.com',
        path: `/v1.0/users/${process.env.MS_USER_EMAIL}/messages?$filter=${encodeURIComponent(filter)}&$select=subject,from,receivedDateTime,bodyPreview,webLink&$orderby=receivedDateTime desc&$top=5`,
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
          'ConsistencyLevel': 'eventual'
        }
      });
      if (res.status === 200) return res.body;
      console.warn('Email filter-by-address failed, falling back to name search. Status:', res.status);
    }

    // Fallback: name-based search, used only when there's no email on file for this person
    const res2 = await fetchJSON({
      hostname: 'graph.microsoft.com',
      path: `/v1.0/users/${process.env.MS_USER_EMAIL}/messages?$search="${encodeURIComponent(name)}"&$select=subject,from,receivedDateTime,bodyPreview,webLink&$top=5`,
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`,
        'ConsistencyLevel': 'eventual'
      }
    });
    return res2.body;
  }

  // Resolve only the attendees on the schedule. Replaces the old behaviour of
  // shipping the entire 20,000-record pool (29MB) to the browser per load.
  if (pathname === '/api/candidates/lookup') {
    const names = String(query.names || '').split('|').map(s => s.trim()).filter(Boolean);
    if (!names.length) return {};
    await getCandidates();
    const found = lookupCandidates(names);
    console.log(`[lookup] ${Object.keys(found).length}/${names.length} matched`);
    return found;
  }

  if (pathname === '/api/candidates/search') {
    await getCandidates();
    const hits = searchCandidates(query.q, Math.min(Number(query.limit) || 25, 50));
    return { query: query.q || '', count: hits.length, results: hits };
  }

  if (pathname === '/api/candidates') {
    // Full crawl on first load or once a day; a single top-up call otherwise.
    // See the incremental sync block above handleAPI().
    // Kept for debugging and backwards compatibility — the dashboard itself
    // now uses /lookup and /search rather than pulling the whole pool.
    return getCandidates();
  }

  if (pathname === '/api/contacts') {
    // Confirmed working endpoint (status 200) — same pagination shape as candidates.
    // Contacts are people like hiring managers or referral sources who aren't candidates
    // themselves, so meetings with them can show real title/company/email instead of guessing.
    if (contactsCache.data && Date.now() < contactsCache.expiry) {
      return contactsCache.data;
    }
    let allContacts = [];
    let page = 1;
    const maxPages = 100; // up to 10,000 contacts — generous headroom, adjust if needed
    while (page <= maxPages) {
      const res = await fetchJSON({
        hostname: 'recruiterflow.com',
        path: `/api/external/contact/list?current_page=${page}&items_per_page=100`,
        method: 'GET',
        headers: { 'rf-api-key': CONFIG.recruiterflow.apiKey }
      });
      const pageData = Array.isArray(res.body) ? res.body : (res.body?.data || []);
      if (!pageData.length) break;
      allContacts = allContacts.concat(pageData);
      if (pageData.length < 100) break;
      page++;
    }
    console.log(`Fetched ${allContacts.length} total contacts across ${page} page(s)`);
    contactsCache.data = allContacts;
    contactsCache.expiry = Date.now() + 20 * 60000; // 20 minutes
    return allContacts;
  }

  if (pathname === '/api/calls') {
    if (callsCache.data && Date.now() < callsCache.expiry) return callsCache.data;
    const token = await getRCToken();
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    const dateFrom = sevenDaysAgo.toISOString().split('T')[0];
    const res = await fetchJSON({
      hostname: 'platform.ringcentral.com',
      path: `/restapi/v1.0/account/~/call-log?type=Voice&dateFrom=${dateFrom}T00:00:00Z&perPage=100`,
      method: 'GET',
      headers: { 'Authorization': `Bearer ${token}` }
    });
    if (res.status === 200) {
      callsCache.data = res.body;
      callsCache.expiry = Date.now() + 60000; // 60s — smooths over simultaneous refreshes from both users
    }
    return res.body;
  }

  if (pathname === '/api/zoom') {
    if (query.fresh) resetZoomToken();   // pick up a newly added scope without redeploying
    const res = await zoomGet('/v2/users/me/meetings?type=scheduled&page_size=10');
    return res.body;
  }

  // ── Zoom AI Companion recaps ───────────────────────────────────────────
  // Lists meetings from the last N days that have an AI summary. Needs the
  // meeting_summary:read:admin scope on the server-to-server OAuth app; if it
  // is missing, Zoom answers 400/4711 and that is surfaced as-is rather than
  // swallowed, so the cause is obvious from the dashboard.
  if (pathname === '/api/zoom/summaries') {
    if (query.fresh) resetZoomToken();
    const days = Math.min(Math.max(Number(query.days) || 14, 1), 90);
    const iso = d => d.toISOString().slice(0, 10);
    const to = new Date();
    const from = new Date(to.getTime() - days * 86400000);
    const res = await zoomGet(
      `/v2/users/me/meeting_summaries?from=${iso(from)}&to=${iso(to)}&page_size=30`);
    if (res.status >= 400) {
      return { error: true, status: res.status, zoom: res.body,
               hint: res.status === 400 || res.body?.code === 4711
                 ? 'Add the meeting_summary:read:admin scope to the Zoom app, then retry with ?fresh=1'
                 : undefined };
    }
    const list = (res.body?.summaries || []).map(s => ({
      uuid: s.meeting_uuid,
      meetingId: s.meeting_id,
      topic: s.meeting_topic,
      start: s.meeting_start_time,
      end: s.meeting_end_time,
      host: s.meeting_host_email
    }));
    return { count: list.length, from: iso(from), to: iso(to), summaries: list };
  }

  // The full recap for one meeting: overview, section details and next steps.
  if (pathname === '/api/zoom/summary') {
    if (!query.uuid) return { error: true, message: 'uuid is required' };
    const res = await zoomGet(`/v2/meetings/${encodeMeetingUuid(query.uuid)}/meeting_summary`);
    if (res.status >= 400) return { error: true, status: res.status, zoom: res.body };
    const b = res.body || {};
    return {
      topic: b.meeting_topic,
      start: b.meeting_start_time,
      overview: b.summary_overview || '',
      details: (b.summary_details || []).map(d => ({ label: d.label, summary: d.summary })),
      nextSteps: b.next_steps || []
    };
  }

  if (pathname === '/api/debug/news') {
    const feeds = [
      { hostname: 'www.insurancejournal.com', path: '/rss/news', source: 'Insurance Journal' },
      { hostname: 'www.claimsjournal.com', path: '/feed', source: 'Claims Journal' }
    ];
    const debug = [];
    for (const feed of feeds) {
      try {
        const xml = await fetchText(feed.hostname, feed.path);
        const items = parseRssItems(xml, feed.source);
        debug.push({ source: feed.source, xmlLength: xml.length, xmlStart: xml.slice(0, 200), itemCount: items.length, firstItem: items[0] || null });
      } catch(e) {
        debug.push({ source: feed.source, error: e.message });
      }
    }
    return { debug };
  }

  if (pathname === '/api/news') {
    const feeds = [
      { hostname: 'www.insurancejournal.com', path: '/rss/news', source: 'Insurance Journal' },
      { hostname: 'www.claimsjournal.com', path: '/feed', source: 'Claims Journal' }
    ];
    const allItems = [];
    for (const feed of feeds) {
      try {
        const xml = await fetchText(feed.hostname, feed.path);
        const items = parseRssItems(xml, feed.source);
        allItems.push(...items);
      } catch(e) {
        console.error(`News feed error [${feed.source}]:`, e.message);
      }
    }
    // Keep only items published in the last 48 hours, newest first
    const cutoff = Date.now() - 48 * 60 * 60 * 1000;
    const fresh = allItems
      .filter(item => item.pubDate && item.pubDate.getTime() > cutoff)
      .sort((a, b) => b.pubDate - a.pubDate)
      .slice(0, 15);
    return { items: fresh };
  }

  return null;
}

// ── Plain HTTPS GET returning raw text (for RSS feeds) ───
function fetchText(hostname, path, redirectCount = 0) {
  return new Promise((resolve, reject) => {
    if (redirectCount > 3) return reject(new Error('Too many redirects'));
    const req = https.request({ hostname, path, method: 'GET', headers: { 'User-Agent': 'RecruiterDashboard/1.0' } }, res => {
      if ([301, 302, 307, 308].includes(res.statusCode) && res.headers.location) {
        const loc = new URL(res.headers.location, `https://${hostname}${path}`);
        res.resume(); // drain response
        return resolve(fetchText(loc.hostname, loc.pathname + loc.search, redirectCount + 1));
      }
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => resolve(data));
    });
    req.on('error', reject);
    req.end();
  });
}

// ── Minimal RSS <item> parser — no external dependencies ───
function parseRssItems(xml, sourceName) {
  const items = [];
  const itemBlocks = xml.split('<item>').slice(1);
  for (const block of itemBlocks) {
    const titleMatch = block.match(/<title>([\s\S]*?)<\/title>/);
    const linkMatch = block.match(/<link>([\s\S]*?)<\/link>/);
    const dateMatch = block.match(/<pubDate>([\s\S]*?)<\/pubDate>/);
    if (!titleMatch || !linkMatch) continue;
    const clean = s => s.replace(/<!\[CDATA\[/g, '').replace(/\]\]>/g, '').trim();
    items.push({
      title: clean(titleMatch[1]),
      link: clean(linkMatch[1]),
      pubDate: dateMatch ? new Date(dateMatch[1]) : null,
      source: sourceName
    });
  }
  return items;
}

async function handleAIProxy(reqBody) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(reqBody);
    const req = https.request({
      hostname: 'api.anthropic.com',
      path: '/v1/messages',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
        'anthropic-version': '2023-06-01',
        'x-api-key': process.env.ANTHROPIC_API_KEY
      }
    }, res => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch(e) { resolve({ error: 'Parse error' }); }
      });
    });
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => { try { resolve(JSON.parse(body)); } catch(e) { resolve({}); } });
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname;
  const query = parsed.query;

  console.log(`${req.method} ${pathname}`);

  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') { res.writeHead(200); res.end(); return; }

  if (pathname === '/' || pathname === '/index.html') {
    try {
      const html = fs.readFileSync(path.join(__dirname, 'public', 'index.html'));
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(html);
    } catch(e) {
      console.error('Could not read index.html:', e.message);
      res.writeHead(500);
      res.end('Could not load dashboard: ' + e.message);
    }
    return;
  }

  if (pathname === '/api/ai' && req.method === 'POST') {
    console.log('AI proxy called');
    try {
      const body = await readBody(req);
      const data = await handleAIProxy(body);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(data));
    } catch(e) {
      console.error('AI proxy error:', e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  if (pathname === '/api/ai') {
    res.writeHead(405, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Method Not Allowed - use POST' }));
    return;
  }

  if (pathname === '/api/overrides' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(loadOverrides()));
    return;
  }

  if (pathname === '/api/overrides' && req.method === 'POST') {
    try {
      const body = await readBody(req);
      const name = (body.name || '').trim();
      const label = (body.label || '').trim();
      if (!name) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'name is required' }));
        return;
      }
      const overrides = loadOverrides();
      if (label) {
        overrides[name] = label;
      } else {
        delete overrides[name]; // empty label clears the override
      }
      saveOverrides(overrides);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, overrides }));
    } catch(e) {
      console.error('Overrides save error:', e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  if (pathname === '/api/notes' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(loadNotes()));
    return;
  }

  if (pathname === '/api/notes' && req.method === 'POST') {
    try {
      const body = await readBody(req);
      const name = String(body.name || '').trim();
      const text = String(body.text == null ? '' : body.text);
      const id = body.id || null;
      if (!name) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'name is required' }));
        return;
      }

      // Local write first, and it decides success. If RecruiterFlow is down,
      // his note is still saved rather than lost to a failed round trip.
      const notes = loadNotes();
      if (text.trim()) {
        notes[name] = { text, id, updated: new Date().toISOString() };
      } else {
        delete notes[name]; // clearing the box removes the note
      }
      saveNotes(notes);

      const rf = text.trim() ? await pushNoteToRecruiterFlow(id, text) : { attempted: false, reason: 'note cleared' };
      console.log(`[notes] saved "${name}" locally; RecruiterFlow: ${rf.attempted ? (rf.ok ? 'ok' : 'failed ' + (rf.status || rf.error)) : 'skipped — ' + rf.reason}`);

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, saved: notes[name] || null, recruiterflow: rf }));
    } catch (e) {
      console.error('Notes save error:', e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  if (pathname.startsWith('/api/')) {
    try {
      const data = await handleAPI(pathname, query);
      if (data === null) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'API route not found' }));
      } else {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(data));
      }
    } catch(e) {
      console.error(`API error [${pathname}]:`, e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  res.writeHead(404);
  res.end('Not found');
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`\n✦ Recruiter Dashboard v3 running on port ${PORT}`);
  console.log('Routes: GET /, GET /api/calendar, GET /api/calendar/tomorrow, GET /api/emails, GET /api/candidates, GET /api/calls, GET /api/zoom, POST /api/ai\n');
});

process.on('SIGTERM', () => {
  console.log('SIGTERM received — uptime: ' + process.uptime() + 's, memory: ' + JSON.stringify(process.memoryUsage()));
  process.exit(0);
});

process.on('uncaughtException', (err) => {
  console.error('UNCAUGHT EXCEPTION:', err.message, err.stack);
});

process.on('unhandledRejection', (reason) => {
  console.error('UNHANDLED REJECTION:', reason);
});
