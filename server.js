const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const url = require('url');
const crypto = require('crypto');

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

/* ═══════════════════════════════════════════════════════════════════════════
   ACCESS CONTROL
   Before this, the dashboard and every API route were open to anyone with the
   URL — /api/candidates returned all 20,000 candidate records, with names,
   email addresses and phone numbers, to an unauthenticated request. The page
   was never the exposure; the API was.

   One shared passcode, set as an environment variable so it is never in this
   repository (which is public). The session cookie is an HMAC of its own
   expiry, so it can't be forged without the secret, and it lasts 90 days —
   this is a dashboard someone opens first thing every morning, and an auth
   scheme that logs him out unpredictably would just get worked around.

   Fails CLOSED: with no passcode configured, nothing is served except a page
   explaining what to set. An auth layer that silently does nothing when
   misconfigured is worse than none, because you'd believe you were covered.
   ═══════════════════════════════════════════════════════════════════════════ */
const PASSCODE = process.env.DASHBOARD_PASSCODE || '';
// Separate secret is optional; derived from the passcode otherwise. Changing
// either one invalidates every existing session, which is the desired
// behaviour if the passcode ever has to be rotated.
const SESSION_SECRET = process.env.SESSION_SECRET || (PASSCODE ? 'v1:' + PASSCODE : '');
const SESSION_COOKIE = 'rd_session';
const SESSION_DAYS = 90;

// Constant-time string compare that doesn't leak length through an exception.
function safeEqual(a, b) {
  const ba = Buffer.from(String(a), 'utf8');
  const bb = Buffer.from(String(b), 'utf8');
  if (ba.length !== bb.length) {
    // Still do a comparison so timing doesn't reveal that lengths differed.
    crypto.timingSafeEqual(ba, ba);
    return false;
  }
  return crypto.timingSafeEqual(ba, bb);
}

function signPayload(p) {
  return crypto.createHmac('sha256', SESSION_SECRET).update(p).digest('base64url');
}

function issueSessionToken() {
  const payload = String(Date.now() + SESSION_DAYS * 86400000);
  return payload + '.' + signPayload(payload);
}

function sessionTokenValid(token) {
  if (!token || !SESSION_SECRET) return false;
  const dot = token.lastIndexOf('.');
  if (dot < 1) return false;
  const payload = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  if (!safeEqual(sig, signPayload(payload))) return false;
  const exp = Number(payload);
  return Number.isFinite(exp) && exp > Date.now();
}

function parseCookies(header) {
  const out = {};
  for (const part of String(header || '').split(';')) {
    const i = part.indexOf('=');
    if (i < 1) continue;
    out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function isAuthed(req) {
  return sessionTokenValid(parseCookies(req.headers.cookie)[SESSION_COOKIE]);
}

// Simple in-memory throttle. Enough to make guessing a shared passcode
// impractical; this is a two-person dashboard, not a login service.
const loginAttempts = new Map();
const LOGIN_MAX = 10;
const LOGIN_WINDOW = 15 * 60000;

function loginBlocked(ip) {
  const rec = loginAttempts.get(ip);
  if (!rec) return false;
  if (Date.now() > rec.resetAt) { loginAttempts.delete(ip); return false; }
  return rec.count >= LOGIN_MAX;
}

function noteFailedLogin(ip) {
  const rec = loginAttempts.get(ip);
  if (!rec || Date.now() > rec.resetAt) {
    loginAttempts.set(ip, { count: 1, resetAt: Date.now() + LOGIN_WINDOW });
  } else {
    rec.count++;
  }
}

function clientIp(req) {
  return String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
         req.socket.remoteAddress || 'unknown';
}

function loginPage({ error, needsSetup } = {}) {
  const body = needsSetup
    ? `<h1>Set a passcode</h1>
       <p class="msg">This dashboard has no passcode configured, so it is serving nothing.</p>
       <ol class="steps">
         <li>Open the service in Render and go to <b>Environment</b>.</li>
         <li>Add a variable named <code>DASHBOARD_PASSCODE</code>, set to whatever you want the passcode to be.</li>
         <li>Save. Render restarts automatically, then this page becomes the login.</li>
       </ol>
       <p class="foot">Pick something you and your dad can both remember. It is never stored in the code.</p>`
    : `<h1>MGMTGlobal</h1>
       <p class="msg">Enter the dashboard passcode.</p>
       <form method="POST" action="/api/login">
         <input type="password" name="passcode" autocomplete="current-password"
                autofocus placeholder="Passcode" aria-label="Passcode">
         <label class="stay"><input type="checkbox" name="remember" value="1" checked> Keep me signed in on this device</label>
         <button type="submit">Sign in</button>
       </form>
       ${error ? `<p class="err">${error}</p>` : ''}`;

  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sign in · Recruitment Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Space+Grotesk:wght@600;700&display=swap" rel="stylesheet">
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#000;min-height:100vh;display:flex;align-items:center;justify-content:center;
       font-family:'Inter',-apple-system,BlinkMacSystemFont,sans-serif;color:#f6f8fb;padding:24px;position:relative;overflow:hidden}
  body::after{content:'';position:fixed;inset:-10%;z-index:0;pointer-events:none;
    background:radial-gradient(circle at 20% 25%,rgba(0,208,132,.14) 0,transparent 34%),
               radial-gradient(circle at 80% 20%,rgba(138,92,255,.12) 0,transparent 32%),
               radial-gradient(circle at 70% 85%,rgba(0,208,132,.10) 0,transparent 36%);
    filter:blur(70px)}
  .card{position:relative;z-index:1;width:100%;max-width:440px;padding:44px 40px;border-radius:26px;
    background-color:rgba(13,15,19,.82);
    background-image:linear-gradient(157deg,rgba(255,255,255,.06),rgba(255,255,255,.01));
    -webkit-backdrop-filter:blur(26px) saturate(165%);backdrop-filter:blur(26px) saturate(165%);
    box-shadow:0 6px 18px rgba(0,0,0,.62),0 30px 70px rgba(0,0,0,.52)}
  .card::before{content:'';position:absolute;inset:0;border-radius:inherit;padding:1px;pointer-events:none;
    background:linear-gradient(147deg,rgba(255,255,255,.42),rgba(255,255,255,.1) 22%,rgba(255,255,255,.02) 46%,rgba(255,255,255,.15));
    -webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);-webkit-mask-composite:xor;
    mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);mask-composite:exclude}
  h1{font-family:'Space Grotesk','Inter',sans-serif;font-size:26px;font-weight:700;letter-spacing:.04em;margin-bottom:8px}
  .msg{font-size:16px;color:#a8b2bf;line-height:1.6;margin-bottom:26px}
  input[type=password]{width:100%;padding:16px 18px;font-family:'Inter',sans-serif;font-size:18px;color:#f6f8fb;
    background:rgba(8,9,12,.9);border:1px solid rgba(255,255,255,.16);border-radius:14px}
  input[type=password]:focus{outline:none;border-color:rgba(0,208,132,.6);box-shadow:0 0 0 4px rgba(0,208,132,.13)}
  input[type=password]::placeholder{color:#8b95a3}
  .stay{display:flex;align-items:center;gap:10px;font-size:15px;color:#a8b2bf;margin:18px 0 22px;cursor:pointer}
  .stay input{width:18px;height:18px;accent-color:#00d084}
  button{width:100%;padding:15px;font-family:'Inter',sans-serif;font-size:16px;font-weight:600;color:#06231a;
    background:linear-gradient(135deg,#00e896,#00b873);border:none;border-radius:14px;cursor:pointer;
    transition:transform .25s cubic-bezier(.22,1,.36,1),filter .25s}
  button:hover{transform:translateY(-2px);filter:brightness(1.07)}
  .err{margin-top:18px;padding:12px 14px;border-radius:12px;font-size:15px;color:#ffb3ae;
    background:rgba(255,69,58,.12);border:1px solid rgba(255,69,58,.4)}
  .steps{margin:0 0 20px 20px;font-size:16px;color:#c3ccd8;line-height:1.85}
  code{font-family:ui-monospace,Menlo,monospace;font-size:14px;background:rgba(255,255,255,.08);
    border:1px solid rgba(255,255,255,.14);border-radius:6px;padding:2px 7px;color:#f6f8fb}
  .foot{font-size:14px;color:#8b95a3;line-height:1.6}
</style></head><body><div class="card">${body}</div></body></html>`;
}

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
/* Which of a notetaker's emails actually carry notes.

   Otter names them plainly ("Meeting Summary for …"). Calendly sends several
   kinds and only some are notes: a recap ("Your meeting recap is now
   available"), an action-item digest ("There are 3 action items from …"), and a
   booking ("A new event has been scheduled", "Updated: Tracy Huber - …"). Its
   reminders and cancellations are not notes and would otherwise land on a
   candidate's card as an empty recap. */
function isRecapMail(subject) {
  const s = String(subject || '');
  if (/it'?s time for|reminder|remember your|cancel+ed|declined|rescheduled\b.*\?/i.test(s)) return false;
  return /summary|notes|meeting recap|action items?|has been scheduled|^\s*updated:|^\s*new event/i.test(s);
}

/* A title for the card's recap header.

   Otter puts the attendees in the subject, so it needs only tidying. Calendly
   does not — "Your meeting recap is now available" names nobody — but its body
   opens with the meeting line ("Dylan Ground and Shane Graham", "Group
   Benefits Producer"), so that becomes the title. A booking names the invitee
   in the subject before the time. */
function recapTitle(msg, text) {
  const subj = String(msg?.subject || '').trim();

  const otter = subj.replace(/^\s*(meeting\s+summary|notes)\s+for\s+/i, '')
                    .replace(/\s+call\s*$/i, '').trim();
  if (/^\s*(meeting\s+summary|notes)\s+for\s+/i.test(subj)) return otter;

  // "Updated: Tracy Huber - 11:00am Fri, Sep 18, 2026 - Brief Consultation"
  const booking = subj.match(/^\s*(?:updated|new event):?\s*(.+?)\s+-\s+\d/i);
  if (booking) return booking[1].trim();

  // Calendly's generic recap subjects: the body's first line is the meeting.
  if (/meeting recap|action items?/i.test(subj)) {
    const first = String(text || '').split('\n').map(l => l.trim())
      .find(l => l.length > 2 && !/^view\b|^summar/i.test(l));
    if (first) return first.replace(/\s+and\s+Shane Graham\s*$/i, '')
                          .replace(/^\s*Shane Graham\s+and\s+/i, '')
                          .slice(0, 80);
    const from = subj.match(/action items?\s+from\s+(.+)$/i);
    if (from) return from[1].trim();
  }
  return subj.slice(0, 80);
}

/* "Jeff Colby, Jacob, & Mark" -> ["Jeff Colby", "Jacob", "Mark"].
   Otter names the attendees in the subject, which is what makes a recap
   attachable to a person at all. Some entries are a first name only; those are
   kept as-is and the matching side decides what is safe to do with them. */
function parseRecapPeople(title) {
  return String(title || '')
    .split(/\s*(?:,|&|\band\b|\+)\s*/i)
    .map(s => s.replace(/\s+/g, ' ').trim())
    .filter(s => s && s.length > 1 && !/^(call|meeting|sync|interview|notes)$/i.test(s));
}

/* Otter's mail is HTML wrapped around the summary. The full body is used when
   Graph returns it, falling back to bodyPreview, which Graph truncates at ~255
   characters — the reason the recap read as a cut-off sentence at first.
   Kept as text: this string is inserted into the page as text, never HTML, so
   the mail's own markup and links cannot execute or reflow the card. */
function recapText(msg) {
  const raw = msg?.body?.content || '';
  if (!raw) return String(msg?.bodyPreview || '').trim();
  let text = raw
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<\/(p|div|tr|li|h[1-6])>/gi, '\n')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/gi, ' ').replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<').replace(/&gt;/gi, '>')
    .replace(/&#39;|&apos;/gi, "'").replace(/&quot;/gi, '"')
    .replace(/[ \t]+/g, ' ')
    .split('\n').map(l => l.trim()).filter(Boolean).join('\n');

  /* Cut the footer, but only at a real footer. "View recording" sits ABOVE the
     summary in Calendly's mail, so treating it as the end marker threw the
     notes away and left the date line behind. Link lines like that are dropped
     individually instead. */
  const cut = text.search(/(Get the Otter|Download Otter|Unsubscribe|©\s*\d{4}\s*(Otter|Calendly)|Powered by Calendly|Manage (your )?(notification|event) (preferences|types)|calendly\.com\/app)/i);
  if (cut > 80) text = text.slice(0, cut);

  const isNoise = l =>
    /^(view recording|view in otter|view recap|view details|join (the )?meeting|reschedule|cancel)\b/i.test(l) ||
    /* The date line and the attendee line. Calendly puts the date and the time
       together ("Friday, September 18, 2026 8:30 – 9 am (CDT)") and lists
       attendees as a name and an address on one line, so anchoring these to the
       end of the line matched neither and the card opened on a date and an
       email address instead of the notes. */
    /^[A-Z][a-z]+day, [A-Z][a-z]+ \d{1,2}, \d{4}\b/.test(l) ||
    /^\d{1,2}(:\d{2})?\s*[–-]\s*\d{1,2}(:\d{2})?\s*(am|pm)\b/i.test(l) ||
    // An address line, not prose: short, contains an @, and isn't a sentence.
    (/@/.test(l) && l.length < 90 && !/[.!?]\s*$/.test(l) && !/\s(and|with|to|from)\s/i.test(l));

  const kept = text.split('\n').filter(l => !isNoise(l)).join('\n').trim();
  let body = kept.length > 60 ? kept : text.trim();

  /* Otter opens with "Shane Graham has shared notes from <title>, <date>",
     which is exactly what the card's own header says. Strip the SENTENCE, not
     the line: Otter's HTML often carries no block breaks, so a whole recap
     de-HTMLs to one long line and removing the first line removed the entire
     summary. Only applied if a real summary survives it. */
  const stripped = body.replace(/^[^.\n]*has shared notes from[^.\n]*\.\s*/i, '').trim();
  if (stripped.length > 40) body = stripped;

  return body.slice(0, 6000);
}

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
  // Zoom states the granted scopes in the token response. Worth keeping: it is
  // the only way to tell "the scope was never added" from "the scope is there
  // and the data genuinely isn't", which otherwise look identical from here.
  tokens.zoomScopes = res.body.scope || null;
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
  tokens.zoomScopes = null;
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
/* RecruiterFlow's city field is whatever LinkedIn had, and LinkedIn deals in
   metros: "Greater Boston", "San Francisco Bay Area", "New York City
   Metropolitan Area". None of those are in a gazetteer of city names, so every
   one of them used to fall back to a state centroid — Relation Insurance had
   one contact pinned in San Francisco and another floating in the middle of
   California. The raw spelling is always tried first, so a real city that
   happens to contain one of these words (Kansas City, Bay City) still wins. */
function titleCase(s) {
  return String(s).replace(/\b[a-z]/g, ch => ch.toUpperCase());
}

function cityCandidates(city) {
  const out = [city.toLowerCase()];
  const push = s => { s = s.replace(/\s+/g, ' ').trim(); if (s && !out.includes(s)) out.push(s); };
  const cleaned = out[0]
    .replace(/\b(greater|metropolitan|metro|area|region|county|and surrounds)\b/g, ' ')
    .replace(/\s+/g, ' ').trim();
  push(cleaned);
  push(cleaned.replace(/\s+bay$/, ''));        // "san francisco bay" → "san francisco"
  push(cleaned.replace(/\s+city$/, ''));       // "new york city" → "new york"
  push(cleaned.split('-')[0]);                 // "dallas-fort worth" → "dallas"
  push(cleaned.split('/')[0]);
  return out;
}

function geoForLocation(L) {
  if (!L || typeof L !== 'object') return null;
  const g = gazetteer();
  const raw = String(L.state || '').trim();
  const code = raw.length === 2 ? raw.toUpperCase() : (g.stateCodes[raw] || null);
  const city = String(L.city || '').trim();

  if (city && code) {
    for (const cand of cityCandidates(city)) {
      const hit = g.cities[cand + '|' + code];
      // The gazetteer's spelling is the one that gets shown, so a pin never
      // reads "Greater Boston, MA" at Boston's coordinates.
      if (hit) return { lat: hit[0], lon: hit[1],
                        city: cand === city.toLowerCase() ? city : titleCase(cand),
                        state: code, precision: 'city' };
    }
  }
  if (code && g.stateCentroids[code]) {
    const ct = g.stateCentroids[code];
    return { lat: ct[0], lon: ct[1], city, state: code, precision: 'state' };
  }
  return null;
}

function geoForCandidate(c) {
  return geoForLocation(c && c.location);
}

/* ── Clients and contacts, consolidated by place ───────────────────────────
   RecruiterFlow's contact list is the client side of the business: brokers,
   hiring managers, the people at the agencies he places into. It carries a
   company per contact, and the same company shows up under several spellings
   — "HUB International", "HUB International (OC)" and "HUB International
   SOCAL" are three records for one firm, and "Ironwood Insurance Services, a
   Marsh McLennan Agency LLC Company" is a fourth way of writing a fifth.
   Plotted raw, one city turns into a pile of overlapping pins that all say
   roughly the same thing.

   So this collapses them twice over: company-name variants fold together
   within a place, and places themselves fold together when they are within a
   short drive of each other. What comes out is one pin per place, carrying
   the companies and the people at them. */

const CONTACT_TTL = Number(process.env.CONTACT_TTL_MS || 20 * 60000);
let contactsInFlight = null;

async function getContacts() {
  if (contactsCache.data && Date.now() < contactsCache.expiry) return contactsCache.data;
  if (contactsInFlight) return contactsInFlight;

  contactsInFlight = (async () => {
    let all = [];
    let page = 1;
    const maxPages = 100;                // up to 10,000 contacts
    while (page <= maxPages) {
      const res = await fetchJSON({
        hostname: 'recruiterflow.com',
        path: `/api/external/contact/list?current_page=${page}&items_per_page=100`,
        method: 'GET',
        headers: { 'rf-api-key': CONFIG.recruiterflow.apiKey }
      });
      const pageData = Array.isArray(res.body) ? res.body : (res.body?.data || []);
      if (!pageData.length) break;
      all = all.concat(pageData);
      if (pageData.length < 100) break;
      page++;
    }
    console.log(`[contacts] ${all.length} contacts across ${page} page(s)`);
    contactsCache.data = all;
    contactsCache.expiry = Date.now() + CONTACT_TTL;
    PLACES.builtFor = null;              // the index is now stale
    return all;
  })().finally(() => { contactsInFlight = null; });

  return contactsInFlight;
}

// Legal suffixes and filler that differ between records for one firm. Words
// that actually distinguish companies — insurance, financial, risk, benefits —
// are deliberately NOT in here; stripping those merged genuinely different
// agencies in testing.
const CO_NOISE = /\b(inc|incorporated|llc|llp|lp|ltd|limited|plc|co|corp|corporation|company|holdings|the)\b/g;

function coKey(name) {
  return String(name || '')
    .toLowerCase()
    .replace(/&/g, ' and ')
    .replace(/[^a-z0-9]+/g, ' ')
    .replace(CO_NOISE, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

// "Ironwood Insurance Services, a Marsh McLennan Agency LLC Company" names its
// own parent. When the parent is also on file at the same place, that is the
// one firm written two ways.
function parentKey(name) {
  const s = String(name || '');
  const m = s.match(/[,(]\s*(?:a|an)\s+(.+?)\s*(?:company|agency|firm|business|partner|brand)\s*[)]?\s*$/i)
         || s.match(/\s+(?:a|an)\s+(.{3,}?)\s+(?:company|partner|brand|division)\s*$/i);
  return m ? coKey(m[1]) : null;
}

function milesBetween(lat1, lon1, lat2, lon2) {
  const R = 3958.8, rad = Math.PI / 180;
  const dLat = (lat2 - lat1) * rad, dLon = (lon2 - lon1) * rad;
  const a = Math.sin(dLat / 2) ** 2 +
            Math.cos(lat1 * rad) * Math.cos(lat2 * rad) * Math.sin(dLon / 2) ** 2;
  return 2 * R * Math.asin(Math.min(1, Math.sqrt(a)));
}

/* Two places merge when they are within this of each other. Set to swallow the
   suburbs of one metro — Irvine and Santa Ana are one pin, Los Angeles and San
   Diego are not — without ever merging across a state line. */
const PLACE_MERGE_MI = 22;

const PLACES = { list: [], unplaced: [], builtFor: null };

function contactPerson(c) {
  const emails = Array.isArray(c.email) ? c.email : (c.email ? [c.email] : []);
  const phones = Array.isArray(c.phone_number) ? c.phone_number : (c.phone_number ? [c.phone_number] : []);
  return {
    id: c.id || null,
    name: rfFullName(c),
    title: String(c.current_designation || '').trim(),
    company: String(c.client_company_name || '').trim(),
    companyId: c.client_company_id || null,
    email: emails[0] || '',
    phone: phones[0] || '',
    lastContacted: c.last_contacted || null
  };
}

// Fold the company-name variants at one place into single firms.
function consolidateCompanies(people) {
  const byKey = new Map();               // key -> { names:Set, ids:Set, people:[] }
  for (const p of people) {
    const raw = p.company || 'No company on file';
    const key = coKey(raw) || raw.toLowerCase();
    let e = byKey.get(key);
    if (!e) byKey.set(key, e = { key, names: new Set(), ids: new Set(), people: [], parents: new Set() });
    e.names.add(raw);
    if (p.companyId) e.ids.add(p.companyId);
    const par = parentKey(raw);
    if (par) e.parents.add(par);
    e.people.push(p);
  }

  /* Shortest key first, so the plain brand becomes the canonical one and the
     regional spellings attach to it rather than the other way round. */
  const keys = [...byKey.keys()].sort((a, b) => a.length - b.length || a.localeCompare(b));
  const canon = new Map();               // key -> canonical key
  const roots = [];
  for (const k of keys) {
    const par = [...byKey.get(k).parents];
    const hit = roots.find(r =>
      k === r ||
      k.startsWith(r + ' ') ||            // "hub international socal" under "hub international"
      par.includes(r));                   // "…, a Marsh McLennan Agency Company"
    if (hit) canon.set(k, hit);
    else { roots.push(k); canon.set(k, k); }
  }

  const merged = new Map();
  for (const [k, e] of byKey) {
    const root = canon.get(k);
    let m = merged.get(root);
    if (!m) merged.set(root, m = { key: root, names: new Set(), ids: new Set(), people: [] });
    e.names.forEach(n => m.names.add(n));
    e.ids.forEach(i => m.ids.add(i));
    m.people.push(...e.people);
  }

  return [...merged.values()].map(m => {
    const names = [...m.names];
    // The shortest spelling reads best on a pin: "HUB International", not
    // "HUB International (OC)". The rest are kept so nothing looks invented.
    const name = names.slice().sort((a, b) => a.length - b.length)[0];
    return {
      name,
      variants: names.filter(n => n !== name),
      ids: [...m.ids],
      people: m.people.sort((a, b) => a.name.localeCompare(b.name))
    };
  }).sort((a, b) => b.people.length - a.people.length || a.name.localeCompare(b.name));
}

async function buildPlaces() {
  const contacts = await getContacts();
  if (PLACES.builtFor === contactsCache.expiry) return PLACES;

  const unplaced = [];
  const seeds = new Map();               // lat|lon|precision -> seed

  for (const c of contacts) {
    const g = geoForLocation(c.location);
    const p = contactPerson(c);
    if (!p.name) continue;
    if (!g) { unplaced.push(p); continue; }
    p.city = g.city || '';
    p.state = g.state || '';
    const k = `${g.lat.toFixed(4)}|${g.lon.toFixed(4)}|${g.precision}`;
    let s = seeds.get(k);
    if (!s) seeds.set(k, s = { lat: g.lat, lon: g.lon, city: g.city, state: g.state,
                               precision: g.precision, people: [] });
    s.people.push(p);
  }

  /* Merge neighbouring seeds into one pin, biggest first so the anchor is the
     city he is most likely to recognise. A state-centroid seed means "somewhere
     in Illinois" — merging that into Chicago would put a name on a location we
     do not actually have, so precision levels never mix. */
  const ordered = [...seeds.values()].sort((a, b) => b.people.length - a.people.length);
  const list = [];
  for (const s of ordered) {
    const host = list.find(l =>
      l.precision === s.precision &&
      l.state === s.state &&
      (s.precision === 'state' ||
       milesBetween(l.lat, l.lon, s.lat, s.lon) <= PLACE_MERGE_MI));
    if (host) {
      host.people.push(...s.people);
      if (s.city && !host.cities.includes(s.city)) host.cities.push(s.city);
    } else {
      list.push({ id: `p${list.length}`, lat: s.lat, lon: s.lon, city: s.city, state: s.state,
                  precision: s.precision, cities: s.city ? [s.city] : [], people: s.people });
    }
  }

  for (const l of list) {
    l.companies = consolidateCompanies(l.people);
    l.peopleCount = l.people.length;
    l.companyCount = l.companies.length;
    // The raw per-person list would duplicate what companies[] already carries.
    delete l.people;
  }
  list.sort((a, b) => b.peopleCount - a.peopleCount);

  PLACES.list = list;
  PLACES.unplaced = unplaced;
  PLACES.builtFor = contactsCache.expiry;
  console.log(`[places] ${contacts.length} contacts → ${list.length} places, ` +
              `${list.reduce((n, l) => n + l.companyCount, 0)} firms, ${unplaced.length} unplaced`);
  return PLACES;
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
        /* The last name has to actually match. Matching on its first letter
           alone, and then falling back to "the first name is unique, close
           enough", is how the calendar block "Shane Graham" became the
           candidate Shane Gustafson of Palo Alto, and how "Focus AM" became a
           company record filed under the first name "Focus". Both were pinned
           on the map as real people while the three contacts he was actually
           meeting that day showed as having no location.

           A prefix is still allowed, because RecruiterFlow stuffs credentials
           into last_name ("Soto M.A., Insurance Agent") and the calendar
           sometimes truncates — but it has to be a prefix of the whole name,
           not of one letter. */
        const last = parts[parts.length - 1];
        const narrowed = sameFirst.filter(c => {
          const cl = rfCleanLastName(c.last_name).toLowerCase();
          return cl === last || (last.length >= 3 && cl.startsWith(last));
        });
        if (narrowed.length === 1) hit = narrowed[0];
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
        path: `/v1.0/users/${process.env.MS_USER_EMAIL}/messages?$filter=${encodeURIComponent(filter)}&$select=subject,from,receivedDateTime,bodyPreview,webLink&$orderby=receivedDateTime%20desc&$top=5`,
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

  /* ── Meeting recaps, from the notetaker that is actually being used ──────
     Zoom's AI Companion is not writing these. Otter.ai joins his calls as a
     participant and emails the summary: Zoom's own API honestly reports six
     summaries, the newest from 14 January, while Otter sent "Meeting Summary
     for Jeff Colby, Jacob, & Mark Call" two days ago. Zoom was the wrong
     product to ask, so this reads the Otter mail instead.

     It is also the better source. Otter puts the attendees in the subject
     line, whereas most of his Zoom calls are titled "Shane Graham's Personal
     Meeting Room" and name nobody, so a Zoom recap frequently could not be
     attached to anyone at all. */
  if (pathname === '/api/recaps') {
    const token = await getMSToken();
    const days = Math.min(Math.max(Number(query.days) || 60, 1), 365);
    const since = new Date(Date.now() - days * 86400000).toISOString();
    const top = Math.min(Math.max(Number(query.limit) || 40, 1), 100);

    /* One request per sender, each filtering on a single property.

       A deterministic $filter, not $search: Microsoft documents search as
       eventually consistent, and it returned different results run to run when
       the email panel relied on it.

       The senders were originally OR'd together with "receivedDateTime ge" and
       sorted, which Graph rejected outright — 400 InefficientFilter, "the
       restriction or sort order is too complex for this operation". Mail
       queries are fussy about combining an OR across one property with a range
       over another and a sort over a third. Splitting it keeps each query to
       the shape Graph reliably serves, and the date bound is dropped from the
       query entirely because the window is enforced below anyway. */
    /* Two notetakers, because he uses two. Otter joins his Zoom calls; Calendly
       writes its own recap and action items for anything booked through it, and
       his first call today was on Teams with Calendly's notes and no Otter at
       all. Reading only Otter left those calls with no notes on the card. */
    const senders = ['no-reply@otter.ai', 'notifications@otter.ai', 'hello@otter.ai',
                     'notifications@calendly.com', 'no-reply@calendly.com'];
    const SELECT = '$select=subject,from,receivedDateTime,bodyPreview,webLink,body';
    const ask = path => fetchJSON({
      hostname: 'graph.microsoft.com',
      path: `/v1.0/users/${process.env.MS_USER_EMAIL}/messages?${path}`,
      method: 'GET',
      headers: { 'Authorization': `Bearer ${token}`, 'ConsistencyLevel': 'eventual' }
    }).catch(e => ({ status: 0, body: { error: { message: e.message } } }));

    /* Several shapes per sender, tried in order, because this mailbox is
       particular about all of them and each failure looked like success.

       - Sender OR'd + date + sort: 400 InefficientFilter outright.
       - Sender + sort: also refused.
       - Sender alone: served, and returned 40 messages — but with no $orderby
         Graph hands back an arbitrary slice, which here was entirely old mail,
         so the window dropped every one and the panel read as empty while the
         query was "working".
       - $search="from:…": served, but the quotes must be literal around an
         encoded term, not themselves encoded.

       So the date bound goes back INTO the query, because without a sort it is
       the only thing that makes the slice recent. A shape counts as good only
       if it returns something inside the window; otherwise the next is tried.
       The window is still re-checked in code below regardless. */
    const inWin = r => (r.body?.value || []).some(m => {
      const t = Date.parse(m.receivedDateTime);
      return Number.isFinite(t) && t >= Date.parse(since);
    });
    const probes = [];
    const pages = await Promise.all(senders.map(async s => {
      const esc = s.replace(/'/g, "''");
      const f = c => `$filter=${encodeURIComponent(c)}&${SELECT}&$top=${top}`;
      const addr = `from/emailAddress/address eq '${esc}'`;
      /* $search leads, because it comes back newest-first in practice and is
         the only shape here that does. filter+date is served and does respect
         the window, but Graph will not sort it, so it returns an arbitrary 40
         of the matching mail: against the real mailbox that gave four genuine
         recaps from July and August while silently omitting the one from two
         days ago. In-window is not the same as recent. */
      const shapes = [
        ['search',           `$search="${encodeURIComponent(`from:${s}`)}"&${SELECT}&$top=${top}`],
        // %20, not a literal space: Node's http client rejects a raw space.
        ['filter+date+sort', f(`${addr} and receivedDateTime ge ${since}`) + '&$orderby=receivedDateTime%20desc'],
        ['filter+date',      f(`${addr} and receivedDateTime ge ${since}`)],
        ['filter+sort',      f(addr) + '&$orderby=receivedDateTime%20desc'],
        ['filter',           f(addr)],
      ];
      /* Take the union of the shapes that work, not the first one.

         Neither shape is dependable alone. filter+date respects the window but
         Graph will not sort it, so it returns an arbitrary 40 of the matching
         mail — against the real mailbox that meant four genuine recaps from
         July and August while silently omitting the one from two days ago.
         $search is recency-biased but eventually consistent: the same request
         returned 33 records one call and 13 the next, and today's Teams recap
         was present in one and absent from the other.

         Merging them covers both, and the de-duplication below already handles
         the overlap. Two successful shapes is enough; there is no point paying
         for more once recent mail is in hand. */
      const good = [];
      for (const [via, path] of shapes) {
        const res = await ask(path);
        if (res.status !== 200) continue;
        const n = (res.body?.value || []).length;
        good.push({ via, res, n, recent: inWin(res) });
        if (good.length >= 2 && good.some(g => g.recent)) break;
      }
      if (!good.length) { probes.push({ s, via: 'failed' }); return { status: 0, body: {} }; }
      probes.push({ s, via: good.map(g => g.via).join('+'),
                    n: good.reduce((t, g) => t + g.n, 0),
                    recent: good.some(g => g.recent) });
      return { status: 200,
               body: { value: good.flatMap(g => g.res.body?.value || []) } };
    }));

    // One dead alias must not take the others down with it; only a clean sweep
    // of failures is reported as an error.
    const ok = pages.filter(r => r.status === 200);
    if (!ok.length) {
      const first = pages[0] || {};
      return { error: true, status: first.status, graph: first.body,
               hint: 'Could not read the mailbox for Otter summary emails.' };
    }
    const res = { status: 200, body: { value: ok.flatMap(r => r.body?.value || []) } };

    /* The window is re-checked here rather than left to the query. Graph's
       $filter on receivedDateTime is reliable, unlike its $search, but Zoom
       silently ignored exactly this kind of date bound on its own endpoint and
       handed back eight-month-old records as though they were current. One
       comparison is cheaper than being wrong the same way twice. */
    const floor = Date.parse(since);
    const items = (res.body?.value || [])
      .filter(m => isRecapMail(m.subject))
      .filter(m => {
        const t = Date.parse(m.receivedDateTime);
        return Number.isFinite(t) && t >= floor;
      })
      .map(m => {
        let text = recapText(m);
        const title = recapTitle(m, text);
        // Calendly's title IS the body's first line, so the card showed it
        // twice — once in the header and again as the opening sentence.
        const lines = text.split('\n');
        if (lines.length > 1 && lines[0].replace(/\s+and\s+Shane Graham\s*$/i, '').trim() === title) {
          const rest = lines.slice(1).join('\n').trim();
          if (rest.length > 40) text = rest;
        }
        const from = (m.from?.emailAddress?.address || '').toLowerCase();
        return {
          id: m.id,
          title,
          subject: m.subject,
          received: m.receivedDateTime,
          webLink: m.webLink,
          source: from.includes('calendly') ? 'calendly' : 'otter',
          // A booking carries what the invitee said they wanted to discuss,
          // which is prep material; a recap is what was actually said.
          kind: /has been scheduled|^\s*(updated|new event)\b/i.test(m.subject || '') ? 'booking' : 'recap',
          people: parseRecapPeople(title),
          text
        };
      });

    // Each sender's query came back sorted, but the merge of three is not, and
    // a message could in principle appear in more than one of them.
    const seen = new Set();
    const list = items
      .filter(r => (r.id && seen.has(r.id)) ? false : (seen.add(r.id), true))
      .sort((a, b) => Date.parse(b.received) - Date.parse(a.received))
      .slice(0, top);
    // `probes` says which query shape each sender needed and how much it
    // returned. Without it, "no recaps" and "the query matched nothing because
    // its syntax was wrong" are the same empty panel.
    return { count: list.length, days, recaps: list,
             probes, raw: (res.body?.value || []).length };
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
    /* Coordinates ride along exactly as they do on the attendee lookup. Without
       them a searched candidate reached the card with no location, so the map
       had nothing to centre on and the whole nearby panel sat out the one case
       it is most useful for. */
    return {
      query: query.q || '', count: hits.length,
      results: hits.map(c => ({ ...c, _geo: geoForCandidate(c) }))
    };
  }

  if (pathname === '/api/candidates') {
    // Full crawl on first load or once a day; a single top-up call otherwise.
    // See the incremental sync block above handleAPI().
    // Kept for debugging and backwards compatibility — the dashboard itself
    // now uses /lookup and /search rather than pulling the whole pool.
    return getCandidates();
  }

  if (pathname === '/api/contacts') {
    /* Coordinates ride along, exactly as they do for candidates. Most of the
       people actually on his calendar are contacts, not candidates — Mick
       Rodgers, Tracy Huber and Carson Natzke were all on today's schedule and
       all three showed as "no location on file" while the map cheerfully
       pinned a company record called "Focus Insurance". The gazetteer already
       places every one of them; nothing was ever asking it to. */
    const list = await getContacts();
    return list.map(c => ({ ...c, _geo: geoForLocation(c.location) }));
  }

  /* Who else is worth knowing about near this person. Takes the coordinates
     the map is already holding for whoever is on the card, and answers with
     the consolidated places around them — one entry per location, each
     carrying the firms and the people at it. */
  if (pathname === '/api/nearby') {
    const { list, unplaced } = await buildPlaces();
    const lat = Number(query.lat), lon = Number(query.lon);
    const statewide = String(query.scope || '') === 'state';
    const st = String(query.state || '').trim().toUpperCase().slice(0, 2);
    const miles = Math.min(Math.max(Number(query.miles) || 50, 5), 3000);

    if (!Number.isFinite(lat) || !Number.isFinite(lon)) {
      return { error: 'lat and lon are required', places: [] };
    }

    const scored = list.map(l => ({ ...l, miles: Math.round(milesBetween(lat, lon, l.lat, l.lon)) }));
    const near = scored
      .filter(l => statewide ? (st ? l.state === st : l.miles <= miles) : l.miles <= miles)
      .sort((a, b) => a.miles - b.miles)
      .slice(0, 40);

    return {
      center: { lat, lon },
      scope: statewide ? 'state' : 'radius',
      miles: statewide ? null : miles,
      state: statewide ? (st || null) : null,
      places: near,
      totals: {
        places: near.length,
        companies: near.reduce((n, l) => n + l.companyCount, 0),
        people: near.reduce((n, l) => n + l.peopleCount, 0),
        indexed: list.length,
        unplaced: unplaced.length
      }
    };
  }

  // The consolidation itself, without a location to centre it on — useful for
  // checking what merged with what.
  if (pathname === '/api/debug/places') {
    const { list, unplaced } = await buildPlaces();
    return {
      places: list.length,
      unplaced: unplaced.length,
      merged: list.flatMap(l => l.companies.filter(c => c.variants.length)
        .map(c => ({ place: `${l.city || l.state}`, kept: c.name, folded: c.variants }))),
      list: list.map(l => ({
        where: [l.city, l.state].filter(Boolean).join(', ') + (l.precision === 'state' ? ' (statewide)' : ''),
        cities: l.cities, people: l.peopleCount, companies: l.companies.map(c => c.name)
      }))
    };
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

    /* Zoom does not honour from/to on this endpoint — measured against the real
       account, days=1 and days=90 returned an identical six records dated eight
       to eleven months outside both windows. The documented path is the
       account-level one; the /users/me variant answers but ignores the dates.
       Try the documented path first, fall back to the old one if the account
       type rejects it, and then filter by date HERE rather than trusting the
       API to have done it. A panel headed "last 14 days" showing an eight-month
       old recap is worse than an empty one. */
    let res = await zoomGet(
      `/v2/meetings/meeting_summaries?from=${iso(from)}&to=${iso(to)}&page_size=30`);
    let endpoint = 'account';
    if (res.status === 404 || res.status === 400) {
      const alt = await zoomGet(
        `/v2/users/me/meeting_summaries?from=${iso(from)}&to=${iso(to)}&page_size=30`);
      // Keep whichever actually answered, preferring the fallback only if it did
      // better, so a genuine scope error still surfaces below.
      if (alt.status < 400) { res = alt; endpoint = 'user'; }
    }
    if (res.status >= 400) {
      // Zoom's granular scope names are not what the docs' older naming
      // suggests: the live API asks for meeting:read:list_summaries:admin,
      // NOT meeting_summary:read:admin. Confirmed against the real account —
      // searching the Marketplace for "summary" does not surface it, so the
      // hint names the exact string to search for.
      return { error: true, status: res.status, zoom: res.body,
               hint: (res.status === 400 || res.body?.code === 4711)
                 ? 'Zoom app is missing a scope. Add meeting:read:list_summaries:admin ' +
                   '(and meeting:read:summary:admin for the full recap), re-activate the ' +
                   'app, then retry with ?fresh=1'
                 : undefined };
    }
    const all = (res.body?.summaries || []).map(s => ({
      uuid: s.meeting_uuid,
      meetingId: s.meeting_id,
      topic: s.meeting_topic,
      start: s.meeting_start_time,
      end: s.meeting_end_time,
      host: s.meeting_host_email
    }));
    // Inclusive of both end dates, in UTC, matching the strings sent upstream.
    const lo = from.getTime() - (from.getTime() % 86400000);
    const hi = to.getTime() - (to.getTime() % 86400000) + 86400000;
    const inWindow = s => {
      const t = Date.parse(s.start);
      return Number.isFinite(t) && t >= lo && t < hi;
    };
    const list = all.filter(inWindow)
                    .sort((a, b) => Date.parse(b.start) - Date.parse(a.start));
    // newest/returned make it obvious when Zoom holds recaps but none are recent,
    // which otherwise looks identical to the integration being broken.
    return { count: list.length, from: iso(from), to: iso(to), summaries: list,
             endpoint, returned: all.length,
             newest: all.length
               ? all.map(s => s.start).sort().slice(-1)[0]
               : null };
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

  /* Raw Zoom recap diagnostics.

     Needed because every interesting failure here looks the same from the
     dashboard: a scope that was never granted, a summary hosted by somebody
     else, a paginated list whose newest page we never asked for, and "AI
     Companion was simply off for that call" all render as an empty panel.

     This reports the scopes Zoom says the token has, follows next_page_token
     to the end rather than trusting one page, and hands back the untouched
     records so the host and the dates can be read directly. Bounded to the one
     Zoom path on purpose — not a general-purpose proxy. */
  if (pathname === '/api/debug/zoom') {
    if (query.fresh !== '0') resetZoomToken();
    const days = Math.min(Math.max(Number(query.days) || 30, 1), 365);
    const iso = d => d.toISOString().slice(0, 10);
    const to = new Date();
    const from = new Date(to.getTime() - days * 86400000);
    const size = Math.min(Math.max(Number(query.page_size) || 30, 1), 300);
    const base = query.path === 'user' ? '/v2/users/me/meeting_summaries'
                                      : '/v2/meetings/meeting_summaries';

    const out = { endpoint: base, from: iso(from), to: iso(to), pages: [], records: [] };
    try { await getZoomToken(); } catch (e) { out.tokenError = e.message; }
    out.grantedScopes = tokens.zoomScopes;

    let token = '', page = 0;
    while (page < 10) {
      const qs = `from=${iso(from)}&to=${iso(to)}&page_size=${size}` +
                 (token ? `&next_page_token=${encodeURIComponent(token)}` : '');
      const res = await zoomGet(`${base}?${qs}`);
      page++;
      out.pages.push({ page, status: res.status,
                       count: (res.body?.summaries || []).length,
                       pageSize: res.body?.page_size,
                       totalRecords: res.body?.total_records,
                       nextPageToken: res.body?.next_page_token || null,
                       error: res.status >= 400 ? res.body : undefined });
      if (res.status >= 400) break;
      out.records.push(...(res.body?.summaries || []));
      token = res.body?.next_page_token || '';
      if (!token) break;
    }
    // Untouched, so the host email and the real dates can be read as Zoom sent
    // them, plus a grouping that answers "whose summaries are these".
    out.total = out.records.length;
    out.byHost = out.records.reduce((m, r) => {
      const h = r.meeting_host_email || r.meeting_host_id || 'unknown';
      m[h] = (m[h] || 0) + 1; return m;
    }, {});
    out.newest = out.records.map(r => r.meeting_start_time).sort().slice(-1)[0] || null;
    return out;
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

  // ── Auth gate ──────────────────────────────────────────────────────────
  // Everything is behind this except the login endpoint itself. /api/* answers
  // 401 JSON so the dashboard's own fetches fail cleanly; everything else gets
  // the login page.
  if (!PASSCODE) {
    // Fail closed. No passcode configured means nothing is served.
    res.writeHead(503, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(loginPage({ needsSetup: true }));
    return;
  }

  if (pathname === '/api/login' && req.method === 'POST') {
    const ip = clientIp(req);
    if (loginBlocked(ip)) {
      res.writeHead(429, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(loginPage({ error: 'Too many attempts. Wait 15 minutes and try again.' }));
      return;
    }
    let raw = '';
    req.on('data', c => raw += c);
    await new Promise(r => req.on('end', r));

    // Accepts the HTML form post and a JSON body, so the page works with or
    // without JavaScript.
    let given = '', remember = true;
    if ((req.headers['content-type'] || '').includes('application/json')) {
      try { const j = JSON.parse(raw); given = j.passcode || ''; remember = j.remember !== false; }
      catch (e) { given = ''; }
    } else {
      const p = new url.URLSearchParams(raw);
      given = p.get('passcode') || '';
      remember = p.get('remember') === '1';
    }

    if (!safeEqual(given, PASSCODE)) {
      noteFailedLogin(ip);
      console.warn(`[auth] failed login from ${ip}`);
      res.writeHead(401, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(loginPage({ error: 'That passcode is not right.' }));
      return;
    }

    loginAttempts.delete(ip);
    // Secure only when the request actually arrived over HTTPS. Render
    // terminates TLS and forwards x-forwarded-proto, so production gets the
    // flag; a plain-HTTP localhost run would otherwise have the browser throw
    // the cookie away and loop back to the login page forever.
    const overHttps = String(req.headers['x-forwarded-proto'] || '').includes('https');
    const cookie = [
      `${SESSION_COOKIE}=${issueSessionToken()}`,
      'Path=/', 'HttpOnly', 'SameSite=Lax',
      overHttps ? 'Secure' : '',
      remember ? `Max-Age=${SESSION_DAYS * 86400}` : ''
    ].filter(Boolean).join('; ');
    console.log(`[auth] login ok from ${ip}`);
    res.writeHead(302, { 'Set-Cookie': cookie, 'Location': '/', 'Cache-Control': 'no-store' });
    res.end();
    return;
  }

  if (pathname === '/api/logout') {
    res.writeHead(302, {
      'Set-Cookie': `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=0`,
      'Location': '/'
    });
    res.end();
    return;
  }

  if (!isAuthed(req)) {
    if (pathname.startsWith('/api/')) {
      res.writeHead(401, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
      res.end(JSON.stringify({ error: 'Not signed in' }));
    } else {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(loginPage());
    }
    return;
  }

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

/* Warm the candidate cache at boot.

   The pool takes a full crawl to build on an empty cache, and every deploy
   starts a fresh process — so without this, the first person to open the
   dashboard after a deploy pays for the whole crawl while looking at a
   half-empty page. Doing it at startup moves that cost to deploy time, when
   nobody is waiting. Failure is logged and otherwise ignored; the first real
   request will simply try again. */
// WARM_CANDIDATES=0 disables it — the cache-timing tests need deterministic
// expiry, and a background refresh landing mid-test moves the goalposts.
if (CONFIG.recruiterflow.apiKey && process.env.WARM_CANDIDATES !== '0') {
  setTimeout(() => {
    const t0 = Date.now();
    getCandidates()
      .then(list => console.log(`[warm] candidate cache ready — ${list.length} records in ${((Date.now()-t0)/1000).toFixed(1)}s`))
      .catch(e => console.warn('[warm] candidate prefetch failed (will retry on demand):', e.message));
  }, 1500);
}

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
