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
const candidatesCache = { data: null, expiry: 0 };

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

async function getZoomToken() {
  if (tokens.zoom) return tokens.zoom;
  const creds = Buffer.from(`${CONFIG.zoom.clientId}:${CONFIG.zoom.clientSecret}`).toString('base64');
  const res = await fetchJSON({
    hostname: 'zoom.us',
    path: `/oauth/token?grant_type=account_credentials&account_id=${CONFIG.zoom.accountId}`,
    method: 'POST',
    headers: { 'Authorization': `Basic ${creds}`, 'Content-Length': 0 }
  }, '');
  tokens.zoom = res.body.access_token;
  return tokens.zoom;
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
    const res = await fetchJSON({
      hostname: 'graph.microsoft.com',
      path: `/v1.0/users/${process.env.MS_USER_EMAIL}/messages?$search="${encodeURIComponent(name)}"&$select=subject,from,receivedDateTime,bodyPreview,webLink&$top=5`,
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`,
        'ConsistencyLevel': 'eventual'
      }
    });
    return res.body;
  }

  if (pathname === '/api/candidates') {
    // Shane has ~15,000 candidates — pulling all of them via ~150 sequential paginated
    // requests is too slow to do on every single page load. Cache the full result for
    // 20 minutes so repeat dashboard opens/refreshes reuse it instantly; only the first
    // load in each 20-minute window pays the full fetch cost.
    if (candidatesCache.data && Date.now() < candidatesCache.expiry) {
      return candidatesCache.data;
    }
    let allCandidates = [];
    let page = 1;
    const maxPages = 200; // safety cap — 200 pages × 100 = up to 20,000 candidates (headroom above his ~15,000)
    while (page <= maxPages) {
      const res = await fetchJSON({
        hostname: 'recruiterflow.com',
        path: `/api/external/candidate/list?current_page=${page}&items_per_page=100`,
        method: 'GET',
        headers: { 'rf-api-key': CONFIG.recruiterflow.apiKey }
      });
      const pageData = Array.isArray(res.body) ? res.body : (res.body?.data || []);
      if (!pageData.length) break; // no more pages
      allCandidates = allCandidates.concat(pageData);
      if (pageData.length < 100) break; // last page was partial, we're done
      page++;
    }
    console.log(`Fetched ${allCandidates.length} total candidates across ${page} page(s)`);
    candidatesCache.data = allCandidates;
    candidatesCache.expiry = Date.now() + 20 * 60000; // 20 minutes
    return allCandidates;
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
    const token = await getZoomToken();
    const res = await fetchJSON({
      hostname: 'api.zoom.us',
      path: '/v2/users/me/meetings?type=scheduled&page_size=10',
      method: 'GET',
      headers: { 'Authorization': `Bearer ${token}` }
    });
    return res.body;
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
