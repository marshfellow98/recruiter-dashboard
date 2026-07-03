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
    clientId: process.env.RC_CLIENT_ID,
    clientSecret: process.env.RC_CLIENT_SECRET
  }
};

const tokens = { ms: null, zoom: null, rc: null };

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
  tokens.ms = res.body.access_token;
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
  if (tokens.rc) return tokens.rc;
  const creds = Buffer.from(`${CONFIG.ringcentral.clientId}:${CONFIG.ringcentral.clientSecret}`).toString('base64');
  const body = encodeForm({ grant_type: 'client_credentials' });
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
  tokens.rc = res.body.access_token;
  return tokens.rc;
}

async function handleAPI(pathname, query) {

  if (pathname === '/api/calendar') {
    const token = await getMSToken();
    const today = new Date().toISOString().split('T')[0];
    const res = await fetchJSON({
      hostname: 'graph.microsoft.com',
      path: `/v1.0/me/calendarView?startDateTime=${today}T00:00:00Z&endDateTime=${today}T23:59:59Z&$select=subject,start,end,bodyPreview,onlineMeeting,attendees&$orderby=start/dateTime&$top=20`,
      method: 'GET',
      headers: { 'Authorization': `Bearer ${token}` }
    });
    return res.body;
  }

  if (pathname === '/api/calendar/tomorrow') {
    const token = await getMSToken();
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    const tDate = tomorrow.toISOString().split('T')[0];
    const res = await fetchJSON({
      hostname: 'graph.microsoft.com',
      path: `/v1.0/me/calendarView?startDateTime=${tDate}T00:00:00Z&endDateTime=${tDate}T23:59:59Z&$select=subject,start,end,bodyPreview,onlineMeeting,attendees&$orderby=start/dateTime&$top=20`,
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
      path: `/v1.0/me/messages?$search="${encodeURIComponent(name)}"&$select=subject,from,receivedDateTime,bodyPreview&$top=5`,
      method: 'GET',
      headers: { 'Authorization': `Bearer ${token}` }
    });
    return res.body;
  }

  if (pathname === '/api/candidates') {
    const res = await fetchJSON({
      hostname: 'recruiterflow.com',
      path: '/api/external/candidate/list?items_per_page=50',
      method: 'GET',
      headers: { 'rf-api-key': CONFIG.recruiterflow.apiKey }
    });
    return res.body;
  }

  if (pathname === '/api/calls') {
    const token = await getRCToken();
    const today = new Date().toISOString().split('T')[0];
    const res = await fetchJSON({
      hostname: 'platform.ringcentral.com',
      path: `/restapi/v1.0/account/~/call-log?type=Voice&dateFrom=${today}T00:00:00Z&perPage=20`,
      method: 'GET',
      headers: { 'Authorization': `Bearer ${token}` }
    });
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

  return null;
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
