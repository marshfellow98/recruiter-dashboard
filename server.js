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
    : `<div class="logo" role="img" aria-label="MGMT Global Consulting"><svg xmlns="http://www.w3.org/2000/svg" viewBox="223.75 373.22 162.93 46.02"><path fill-rule="evenodd" fill="#ffffff" d="M 281.261719 412.769531 C 280.917969 413.050781 280.503906 413.191406 280.15625 413.191406 L 277.738281 413.191406 L 277.738281 407.800781 L 280.433594 407.871094 C 281.054688 407.871094 281.46875 408.429688 281.539062 408.851562 C 281.675781 409.480469 281.402344 410.039062 280.847656 410.320312 C 281.46875 410.601562 281.746094 410.949219 281.816406 411.441406 C 281.953125 411.929688 281.746094 412.421875 281.261719 412.769531 Z M 280.019531 410.109375 C 280.570312 410.109375 280.847656 409.621094 280.847656 409.199219 C 280.847656 408.78125 280.503906 408.429688 280.019531 408.429688 L 278.496094 408.429688 L 278.496094 410.039062 Z M 280.503906 412.488281 C 280.988281 412.351562 281.195312 411.859375 281.125 411.511719 C 280.917969 410.671875 279.742188 410.738281 278.496094 410.808594 L 278.496094 412.488281 C 279.1875 412.558594 279.8125 412.628906 280.503906 412.488281 Z M 371.679688 413.121094 C 371.542969 413.191406 371.058594 413.261719 370.851562 413.121094 L 367.742188 408.921875 L 367.742188 413.261719 C 367.464844 413.261719 367.257812 413.261719 367.050781 413.191406 L 366.980469 407.871094 L 367.878906 407.871094 L 370.921875 411.929688 L 370.988281 407.800781 L 371.679688 407.871094 Z M 328.613281 413.191406 C 328.40625 413.261719 327.992188 413.328125 327.855469 413.121094 L 324.8125 409.058594 L 324.742188 413.261719 L 324.050781 413.261719 L 324.050781 407.800781 L 324.882812 407.871094 L 327.921875 412.070312 L 327.992188 407.871094 L 328.683594 407.871094 Z M 319.972656 410.53125 C 319.972656 412.070312 318.660156 413.328125 317.140625 413.328125 C 315.617188 413.328125 314.304688 412.070312 314.304688 410.53125 C 314.304688 408.921875 315.617188 407.660156 317.140625 407.660156 C 318.660156 407.660156 319.972656 408.921875 319.972656 410.53125 Z M 315.894531 412.28125 C 316.863281 412.910156 318.039062 412.769531 318.730469 411.929688 C 319.351562 411.160156 319.421875 410.109375 318.800781 409.199219 C 318.316406 408.429688 317.207031 408.078125 316.242188 408.570312 C 315.550781 408.921875 315.136719 409.550781 315.066406 410.25 C 314.996094 411.019531 315.273438 411.789062 315.894531 412.28125 Z M 273.796875 410.53125 C 273.796875 412.070312 272.554688 413.398438 271.03125 413.398438 C 269.441406 413.398438 268.199219 412.070312 268.199219 410.53125 C 268.199219 408.921875 269.441406 407.660156 271.03125 407.660156 C 272.554688 407.660156 273.796875 408.921875 273.796875 410.53125 Z M 272.96875 411.300781 C 273.382812 410.109375 272.828125 408.921875 271.792969 408.5 C 270.753906 408.078125 269.511719 408.570312 269.097656 409.621094 C 268.613281 410.808594 269.097656 412.070312 270.132812 412.488281 C 271.171875 412.910156 272.484375 412.558594 272.96875 411.300781 Z M 257.070312 410.878906 L 255.6875 410.878906 L 255.753906 410.25 L 257.828125 410.25 L 257.828125 412.769531 C 256.859375 413.261719 255.6875 413.46875 254.648438 413.121094 C 253.542969 412.769531 252.921875 411.71875 252.851562 410.601562 C 252.851562 409.480469 253.472656 408.359375 254.578125 407.941406 C 255.617188 407.519531 256.722656 407.660156 257.621094 408.359375 C 257.550781 408.640625 257.414062 408.851562 257.136719 408.988281 C 256.238281 408.078125 254.71875 408.148438 254.027344 409.269531 C 253.265625 410.320312 253.542969 411.71875 254.648438 412.351562 C 255.339844 412.839844 256.308594 412.699219 257.070312 412.351562 Z M 379.699219 410.878906 L 378.386719 410.878906 L 378.386719 410.25 L 380.390625 410.25 L 380.390625 412.769531 C 379.421875 413.261719 378.316406 413.46875 377.28125 413.121094 C 375.828125 412.628906 375.207031 411.019531 375.621094 409.621094 C 376.105469 408.21875 377.558594 407.449219 379.007812 407.800781 C 379.492188 407.941406 379.976562 408.078125 380.320312 408.429688 L 379.769531 408.988281 C 379.007812 408.21875 377.832031 408.148438 377.003906 408.851562 C 376.175781 409.550781 375.96875 410.738281 376.589844 411.71875 C 377.210938 412.769531 378.730469 412.910156 379.699219 412.28125 Z M 289.488281 411.789062 L 286.792969 411.789062 L 286.171875 413.121094 L 285.339844 413.191406 L 287.761719 407.800781 C 288.039062 407.730469 288.246094 407.800781 288.453125 407.800781 L 290.800781 413.191406 L 290.042969 413.191406 Z M 289.144531 411.019531 L 288.105469 408.78125 L 287.070312 411.089844 C 287.898438 411.089844 288.453125 411.160156 289.144531 411.019531 Z M 344.03125 407.800781 L 344.789062 407.800781 L 344.722656 411.371094 C 344.722656 412.628906 343.753906 413.261719 342.578125 413.261719 C 341.472656 413.261719 340.367188 412.699219 340.367188 411.441406 L 340.296875 407.800781 L 341.058594 407.800781 L 341.058594 411.230469 C 341.058594 412.140625 341.75 412.628906 342.578125 412.628906 C 343.40625 412.558594 344.03125 412.070312 344.03125 411.230469 Z M 335.734375 412.910156 C 334.699219 413.539062 333.382812 413.328125 332.554688 412.488281 C 332.625 412.210938 332.902344 412.070312 333.109375 411.929688 C 333.660156 412.628906 334.699219 412.839844 335.390625 412.28125 C 335.597656 412.140625 335.664062 411.789062 335.664062 411.578125 C 335.597656 411.300781 335.390625 411.089844 335.113281 411.019531 L 333.59375 410.53125 C 333.039062 410.320312 332.761719 409.898438 332.695312 409.339844 C 332.695312 408.78125 332.902344 408.289062 333.382812 408.011719 C 334.351562 407.449219 335.457031 407.589844 336.289062 408.289062 C 336.148438 408.570312 335.941406 408.710938 335.734375 408.851562 C 335.25 408.359375 334.558594 408.148438 333.9375 408.429688 C 333.59375 408.570312 333.453125 408.851562 333.453125 409.128906 C 333.453125 409.480469 333.660156 409.761719 334.007812 409.898438 L 335.320312 410.320312 C 335.875 410.460938 336.355469 410.878906 336.425781 411.371094 C 336.496094 411.929688 336.289062 412.628906 335.734375 412.910156 Z M 310.367188 412 C 310.574219 411.789062 310.988281 412.210938 310.917969 412.351562 C 310.503906 413.050781 309.742188 413.191406 308.984375 413.261719 C 307.394531 413.328125 306.21875 412.210938 306.148438 410.601562 C 306.078125 409.269531 306.839844 408.148438 308.152344 407.800781 C 309.121094 407.519531 310.226562 407.730469 310.917969 408.570312 L 310.367188 408.988281 C 309.8125 408.359375 309.050781 408.21875 308.292969 408.429688 C 307.601562 408.640625 307.046875 409.269531 306.910156 410.109375 C 306.769531 411.019531 307.117188 411.929688 307.875 412.351562 C 308.707031 412.769531 309.675781 412.699219 310.367188 412 Z M 356.613281 413.191406 C 356.335938 413.191406 356.105469 413.191406 355.921875 413.191406 L 355.921875 408.429688 L 354.191406 408.429688 L 354.191406 407.800781 L 358.339844 407.800781 L 358.339844 408.429688 L 356.613281 408.429688 Z M 297.785156 412.488281 C 297.832031 412.722656 297.832031 412.957031 297.785156 413.191406 L 294.464844 413.191406 L 294.464844 407.800781 L 295.15625 407.800781 L 295.15625 412.488281 Z M 352.1875 412.488281 L 352.257812 413.191406 L 348.871094 413.191406 L 348.871094 407.800781 L 349.558594 407.800781 L 349.628906 412.488281 Z M 265.226562 412.488281 L 265.226562 413.191406 L 261.90625 413.191406 L 261.90625 407.800781 L 262.597656 407.800781 L 262.597656 412.488281 Z M 362.765625 407.800781 L 362.765625 413.191406 L 362.003906 413.191406 L 362.003906 407.800781 Z M 362.765625 407.800781 "></path><path fill-rule="evenodd" fill="#ffffff" d="M 270.203125 402.828125 C 266.816406 398 263.636719 394.011719 260.386719 389.390625 C 259.488281 392.75 258.589844 396.390625 257.207031 402.128906 C 256.722656 402.058594 256.03125 401.988281 255.269531 401.988281 C 254.511719 401.988281 253.75 402.058594 253.335938 402.128906 C 255.617188 394.570312 257.898438 387.078125 259.832031 379.449219 L 260.179688 379.449219 C 264.257812 385.398438 268.199219 390.511719 272.136719 395.96875 C 276.285156 390.441406 279.878906 385.398438 283.476562 379.449219 L 283.890625 379.449219 C 285.964844 387.148438 288.246094 394.78125 290.527344 402.128906 C 289.902344 402.058594 288.519531 401.988281 287.140625 401.988281 C 285.757812 401.988281 284.304688 402.058594 283.683594 402.128906 C 282.507812 396.808594 281.261719 392.679688 280.433594 388.96875 C 277.183594 393.660156 274.003906 397.648438 270.546875 402.828125 Z M 296.816406 390.859375 C 296.816406 396.808594 301.378906 400.660156 308.429688 400.660156 C 310.574219 400.660156 312.714844 400.378906 314.304688 399.75 C 314.238281 394.78125 314.027344 393.589844 313.753906 391.839844 C 314.859375 391.910156 315.964844 391.980469 317 391.980469 C 318.039062 391.980469 319.144531 391.910156 320.179688 391.839844 C 319.90625 393.660156 319.699219 394.851562 319.699219 400.941406 C 318.589844 401.148438 317.347656 401.570312 315.964844 401.851562 C 313.683594 402.339844 311.195312 402.828125 308.359375 402.828125 C 298.542969 402.828125 290.042969 399.121094 290.042969 390.859375 C 290.042969 383.511719 297.09375 379.449219 308.292969 379.449219 C 311.816406 379.449219 315.34375 379.941406 318.382812 381.058594 C 318.800781 381.128906 319.144531 381.410156 319.214844 381.761719 L 319.765625 386.449219 L 319.351562 386.519531 C 317.625 383.789062 313.960938 381.691406 308.292969 381.691406 C 301.933594 381.691406 296.886719 384.699219 296.886719 390.859375 Z M 338.636719 402.828125 C 335.320312 398 332.140625 394.011719 328.890625 389.390625 C 327.921875 392.75 327.09375 396.390625 325.710938 402.128906 C 325.226562 402.058594 324.46875 401.988281 323.777344 401.988281 C 323.015625 401.988281 322.253906 402.058594 321.769531 402.128906 C 324.050781 394.570312 326.332031 387.078125 328.339844 379.449219 L 328.683594 379.449219 C 332.695312 385.398438 336.703125 390.511719 340.644531 395.96875 C 344.789062 390.441406 348.386719 385.398438 351.980469 379.449219 L 352.394531 379.449219 C 354.46875 387.148438 356.679688 394.78125 359.03125 402.128906 C 358.410156 402.058594 357.027344 401.988281 355.644531 401.988281 C 354.261719 401.988281 352.808594 402.058594 352.1875 402.128906 C 351.011719 396.808594 349.769531 392.679688 348.871094 388.96875 C 345.6875 393.660156 342.441406 397.648438 339.054688 402.828125 Z M 367.601562 402.128906 C 367.742188 399.960938 368.015625 396.949219 368.015625 391 C 368.015625 386.519531 367.949219 384.210938 367.808594 382.671875 L 360.757812 382.671875 C 359.445312 382.671875 358.546875 383.160156 357.648438 384.488281 L 357.234375 384.421875 L 357.992188 380.078125 L 358.410156 380.078125 C 359.101562 380.148438 359.792969 380.148438 360.691406 380.148438 L 381.21875 380.148438 C 382.1875 380.148438 383.085938 380.148438 383.570312 380.078125 L 383.984375 380.078125 L 384.675781 384.421875 L 384.332031 384.488281 C 383.433594 383.160156 382.464844 382.671875 381.21875 382.671875 L 374.167969 382.671875 C 374.03125 384.210938 373.960938 386.519531 373.960938 391 C 373.960938 396.949219 374.238281 399.960938 374.378906 402.128906 C 373.269531 402.058594 372.097656 401.988281 370.988281 401.988281 C 369.882812 401.988281 368.707031 402.058594 367.601562 402.128906 Z M 367.601562 402.128906 "></path><path fill-rule="evenodd" fill="#E1A13F" d="M 253.679688 415.429688 Z M 243.726562 417.109375 C 240.683594 416.828125 237.851562 415.851562 235.292969 414.308594 C 233.082031 412.980469 231.285156 411.160156 230.109375 408.921875 C 228.378906 405.558594 229.625 402.058594 232.183594 399.539062 C 233.839844 397.929688 235.707031 396.671875 237.78125 395.691406 C 242 393.660156 246.5625 392.398438 251.261719 392.050781 C 251.539062 392.003906 251.816406 391.980469 252.089844 391.980469 L 250.570312 397.300781 C 247.484375 397.625 244.488281 398.375 241.585938 399.539062 C 238.679688 400.730469 235.222656 402.761719 233.980469 405.769531 C 233.496094 407.101562 233.359375 408.710938 234.324219 409.96875 C 234.464844 408.21875 235.085938 406.960938 236.261719 405.910156 C 239.09375 403.460938 243.863281 401.5 247.527344 401.078125 C 248.152344 401.011719 248.773438 400.941406 249.394531 401.011719 L 248.21875 405.351562 L 248.011719 406.050781 L 244.972656 406.609375 C 243.3125 406.890625 241.792969 407.449219 240.476562 408.359375 C 240.433594 408.359375 240.410156 408.359375 240.410156 408.359375 C 239.648438 408.851562 238.957031 409.621094 238.75 410.53125 C 238.542969 411.578125 238.957031 412.558594 239.578125 413.398438 C 241.238281 415.710938 244.417969 416.339844 247.183594 416.410156 C 249.394531 416.480469 251.539062 415.988281 253.679688 415.429688 C 250.570312 417.109375 247.183594 417.460938 243.726562 417.109375 Z M 256.859375 375.460938 L 255.480469 380.21875 C 254.371094 380.078125 238.613281 377.910156 230.109375 388.898438 C 227.34375 392.46875 226.238281 396.25 225.753906 399.050781 C 225.683594 395.828125 226.167969 391.628906 228.378906 387.570312 C 233.21875 378.75 244.417969 374.058594 256.859375 375.460938 Z M 254.648438 383.089844 L 252.988281 388.898438 C 240.546875 389.390625 230.800781 394.289062 228.65625 401.640625 C 228.242188 402.96875 228.035156 404.648438 228.378906 406.75 C 226.652344 401.078125 227.757812 397.160156 228.378906 395.480469 C 231.492188 387.289062 242 381.96875 254.648438 383.089844 Z M 254.648438 383.089844 "></path></svg></div>
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
<link rel="icon" href="data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20viewBox%3D%22213.15%20368.07%2056.3%2056.3%22%3E%3Crect%20x%3D%22213.15%22%20y%3D%22368.07%22%20width%3D%2256.3%22%20height%3D%2256.3%22%20rx%3D%2212.39%22%20fill%3D%22%2305070A%22%2F%3E%3Cpath%20fill-rule%3D%22evenodd%22%20fill%3D%22%23E1A13F%22%20d%3D%22M%20253.679688%20415.429688%20Z%20M%20243.726562%20417.109375%20C%20240.683594%20416.828125%20237.851562%20415.851562%20235.292969%20414.308594%20C%20233.082031%20412.980469%20231.285156%20411.160156%20230.109375%20408.921875%20C%20228.378906%20405.558594%20229.625%20402.058594%20232.183594%20399.539062%20C%20233.839844%20397.929688%20235.707031%20396.671875%20237.78125%20395.691406%20C%20242%20393.660156%20246.5625%20392.398438%20251.261719%20392.050781%20C%20251.539062%20392.003906%20251.816406%20391.980469%20252.089844%20391.980469%20L%20250.570312%20397.300781%20C%20247.484375%20397.625%20244.488281%20398.375%20241.585938%20399.539062%20C%20238.679688%20400.730469%20235.222656%20402.761719%20233.980469%20405.769531%20C%20233.496094%20407.101562%20233.359375%20408.710938%20234.324219%20409.96875%20C%20234.464844%20408.21875%20235.085938%20406.960938%20236.261719%20405.910156%20C%20239.09375%20403.460938%20243.863281%20401.5%20247.527344%20401.078125%20C%20248.152344%20401.011719%20248.773438%20400.941406%20249.394531%20401.011719%20L%20248.21875%20405.351562%20L%20248.011719%20406.050781%20L%20244.972656%20406.609375%20C%20243.3125%20406.890625%20241.792969%20407.449219%20240.476562%20408.359375%20C%20240.433594%20408.359375%20240.410156%20408.359375%20240.410156%20408.359375%20C%20239.648438%20408.851562%20238.957031%20409.621094%20238.75%20410.53125%20C%20238.542969%20411.578125%20238.957031%20412.558594%20239.578125%20413.398438%20C%20241.238281%20415.710938%20244.417969%20416.339844%20247.183594%20416.410156%20C%20249.394531%20416.480469%20251.539062%20415.988281%20253.679688%20415.429688%20C%20250.570312%20417.109375%20247.183594%20417.460938%20243.726562%20417.109375%20Z%20M%20256.859375%20375.460938%20L%20255.480469%20380.21875%20C%20254.371094%20380.078125%20238.613281%20377.910156%20230.109375%20388.898438%20C%20227.34375%20392.46875%20226.238281%20396.25%20225.753906%20399.050781%20C%20225.683594%20395.828125%20226.167969%20391.628906%20228.378906%20387.570312%20C%20233.21875%20378.75%20244.417969%20374.058594%20256.859375%20375.460938%20Z%20M%20254.648438%20383.089844%20L%20252.988281%20388.898438%20C%20240.546875%20389.390625%20230.800781%20394.289062%20228.65625%20401.640625%20C%20228.242188%20402.96875%20228.035156%20404.648438%20228.378906%20406.75%20C%20226.652344%20401.078125%20227.757812%20397.160156%20228.378906%20395.480469%20C%20231.492188%20387.289062%20242%20381.96875%20254.648438%20383.089844%20Z%20M%20254.648438%20383.089844%20%22%2F%3E%3C%2Fsvg%3E"><title>Sign in · Recruitment Dashboard</title>
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
  /* The kit's dark-background logo, which is what the sign-in screen should
     carry rather than the name typed out. */
  .logo{display:block;margin:0 auto 14px;max-width:230px}
  .logo svg{display:block;width:100%;height:auto}
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
/* ── Where his typing actually lives ───────────────────────────────────────
   Render gives a service an ephemeral filesystem: "any changes you make to a
   service's local files are lost every time the service redeploys or
   restarts". These two files were being written next to the code, which means
   every deploy threw away every note on anyone without a RecruiterFlow record
   and every label correction he had made. We deployed eight times in one day.

   Three things now stand between him and that:
     - DATA_DIR, so attaching a Render disk later is a setting rather than a
       code change;
     - the RecruiterFlow push, which already carried candidate notes somewhere
       permanent and now carries contact notes too;
     - and the browser, which keeps its own copy and offers it back when the
       server comes up empty. That one needs no paid plan and is what actually
       saves him today.
   A boot line says which of these is in play, because silent data loss is the
   kind you only discover when you needed the note. */
const DATA_DIR = process.env.DATA_DIR || __dirname;
const DURABLE = !!process.env.DATA_DIR;
const BOOT_AT = Date.now();

const OVERRIDES_FILE = path.join(DATA_DIR, 'overrides.json');

function loadOverrides() {
  try {
    return JSON.parse(fs.readFileSync(OVERRIDES_FILE, 'utf8'));
  } catch(e) {
    return {}; // file doesn't exist yet, or is invalid — start fresh
  }
}

function saveOverrides(overrides) {
  try { fs.mkdirSync(DATA_DIR, { recursive: true }); } catch (e) {}
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
const NOTES_FILE = path.join(DATA_DIR, 'notes.json');

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
  try { fs.mkdirSync(DATA_DIR, { recursive: true }); } catch (e) {}
  const tmp = NOTES_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(notes, null, 2));
  fs.renameSync(tmp, NOTES_FILE);
}

/* This was pushing notes to candidate/update as `{id, notes: [text]}`, and
   RecruiterFlow's own spec does not list `notes` among the properties that
   endpoint accepts — the documented behaviour is "a complete update... any
   existing data in the provided key will be wiped out", for keys it knows.
   An unknown key is simply ignored, which means every note this dashboard has
   ever "saved to RecruiterFlow" went nowhere: the API answered 200, the UI
   said "Saved here and in RecruiterFlow", and the only real copy was the local
   file that Render wipes on each deploy.

   There is a proper endpoint for this — candidate/notes/add and
   contact/notes/add, taking {id, value} — and it appends rather than
   replacing, which is what a note should do. */
async function pushNoteToRecruiterFlow(id, text, kind = 'candidate') {
  if (!id) return { attempted: false, reason: 'no RecruiterFlow id on this record' };
  if (!CONFIG.recruiterflow.apiKey) return { attempted: false, reason: 'no API key configured' };
  const payload = JSON.stringify({ id: Number(id) || id, value: String(text) });
  try {
    const res = await fetchJSON({
      hostname: 'recruiterflow.com',
      path: kind === 'contact' ? '/api/external/contact/notes/add'
                               : '/api/external/candidate/notes/add',
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

/* ── Putting someone into RecruiterFlow ────────────────────────────────────
   Most of the people on his calendar are already in one of the two lists, but
   not all: today's only outside meeting was with someone writing from a gmail
   address who appears in neither, which means no location on the map, no
   history, and nowhere to hang a note. The dashboard already knows her name,
   her email and the meeting she is attached to, so it can offer to file her.

   Field names and the response shape come from RecruiterFlow's own spec:
     candidate/add → first_name, last_name, email[{email,is_primary}],
                     phone_number[{phone_number,type}], title, organization,
                     source, location{city,state,country}, tags
     contact/add   → the same, with client_company instead of location
     both answer   → { RESULT: "SUCCESS", data: { id } }
   Note that a contact takes no location of its own; a contact is placed on the
   map through the company they belong to. */
async function createInRecruiterFlow(rec, kind) {
  if (!CONFIG.recruiterflow.apiKey) return { ok: false, error: 'no API key configured' };

  const first = String(rec.firstName || '').trim();
  const last = String(rec.lastName || '').trim();
  if (!first && !last) return { ok: false, error: 'a name is required' };

  const body = {
    first_name: first,
    last_name: last,
    title: String(rec.title || '').trim() || undefined,
    source: 'Recruiter Dashboard',
    tags: ['Added from dashboard']
  };
  if (rec.email) body.email = [{ email: String(rec.email).trim(), is_primary: 1 }];
  if (rec.phone) body.phone_number = [{ phone_number: String(rec.phone).trim(), type: 1 }];

  if (kind === 'contact') {
    if (rec.company) body.client_company = String(rec.company).trim();
  } else {
    if (rec.company) body.organization = String(rec.company).trim();
    const city = String(rec.city || '').trim();
    const state = String(rec.state || '').trim();
    if (city || state) body.location = { city, state, country: 'United States' };
  }

  const payload = JSON.stringify(body);
  const res = await fetchJSON({
    hostname: 'recruiterflow.com',
    path: kind === 'contact' ? '/api/external/contact/add' : '/api/external/candidate/add',
    method: 'POST',
    headers: {
      'rf-api-key': CONFIG.recruiterflow.apiKey,
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(payload)
    }
  }, payload);

  const b = res.body || {};
  const id = (b.data && b.data.id) || b.id || null;
  const ok = (res.status >= 200 && res.status < 300) &&
             (!b.RESULT || /success/i.test(b.RESULT)) && !!id;
  return ok
    ? { ok: true, id, kind, sent: body }
    : { ok: false, status: res.status, error: b.message || b.RESULT || `RecruiterFlow returned ${res.status}`,
        body: b };
}

// Is this person already on file? Checked before creating, because a duplicate
// in a book of business is worse than a missing record.
function findExistingPerson(name, email) {
  const lower = String(name || '').trim().toLowerCase();
  const mail = String(email || '').trim().toLowerCase();
  const sameMail = list => (list || []).find(c => {
    const arr = Array.isArray(c.email) ? c.email : (c.email ? [c.email] : []);
    return mail && arr.some(e => String(e && e.email ? e.email : e).toLowerCase() === mail);
  });

  const cands = candidatesCache.data || [];
  const byName = cands.find(c => rfFullName(c).toLowerCase() === lower);
  if (byName) return { where: 'candidates', id: byName.id, name: rfFullName(byName), on: 'name' };
  const byMail = sameMail(cands);
  if (byMail) return { where: 'candidates', id: byMail.id, name: rfFullName(byMail), on: 'email' };

  const cts = contactsCache.data || [];
  const ctName = cts.find(c => rfFullName(c).toLowerCase() === lower);
  if (ctName) return { where: 'contacts', id: ctName.id, name: rfFullName(ctName), on: 'name' };
  const ctMail = sameMail(cts);
  if (ctMail) return { where: 'contacts', id: ctMail.id, name: rfFullName(ctMail), on: 'email' };

  return null;
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
    // RingCentral states the app's permissions in the token response. Reading
    // them here is what lets the dashboard know whether it can ring his phone
    // or has to hand the number to the desktop dialer — without finding out by
    // placing a call and failing.
    tokens.rcScopes = String(res.body.scope || '');
    console.log('RC token acquired successfully; scopes:', tokens.rcScopes || '(none reported)');
  } else {
    console.error('RC token error:', JSON.stringify(res.body));
  }
  return tokens.rc;
}

function rcCanRingOut() { return /RingOut/i.test(tokens.rcScopes || ''); }

/* RingOut calls his own phone first and only then dials the other party, so
   the number he is calling from is his, and the call lands in RingCentral's
   log like any other. It needs to know which of his numbers to ring. */
async function rcCallerId() {
  if (process.env.RC_CALLER_ID) return process.env.RC_CALLER_ID;
  if (tokens.rcFrom) return tokens.rcFrom;
  const token = await getRCToken();
  const res = await fetchJSON({
    hostname: 'platform.ringcentral.com',
    path: '/restapi/v1.0/account/~/extension/~/phone-number?perPage=25',
    method: 'GET',
    headers: { 'Authorization': `Bearer ${token}` }
  });
  const nums = (res.body && res.body.records) || [];
  const pick = nums.find(n => n.usageType === 'DirectNumber')
            || nums.find(n => n.usageType === 'MainCompanyNumber')
            || nums[0];
  tokens.rcFrom = pick ? pick.phoneNumber : null;
  return tokens.rcFrom;
}

// Digits only, then E.164. RecruiterFlow already stores most numbers as
// +1XXXXXXXXXX, but a hand-typed "(614) 555-0211" has to work too.
function toE164(raw) {
  const s = String(raw || '').trim();
  if (/^\+[1-9]\d{7,14}$/.test(s)) return s;
  const d = s.replace(/\D/g, '');
  if (d.length === 10) return '+1' + d;
  if (d.length === 11 && d[0] === '1') return '+' + d;
  return null;
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

/* ── Which day is it where he is ───────────────────────────────────────────
   The calendar routes used to subtract a hardcoded five hours to get Central
   time. That is right for half the year: CDT is UTC-5, CST is UTC-6. From the
   first Sunday in November the boundaries would have slipped by an hour, and
   an early-morning or late-evening meeting would have been filed under the
   wrong day — the same class of bug that was once cutting off everything
   after 7pm.

   These ask the runtime for the real offset instead, which handles the
   changeover without anyone having to remember it. */
const BIZ_TZ = process.env.BIZ_TZ || 'America/Chicago';

function tzParts(date, tz) {
  const dtf = new Intl.DateTimeFormat('en-US', {
    timeZone: tz, hour12: false,
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit'
  });
  const p = {};
  for (const x of dtf.formatToParts(date)) if (x.type !== 'literal') p[x.type] = x.value;
  return p;
}

// How far the zone is from UTC at this instant, in milliseconds.
function tzOffsetMs(date, tz = BIZ_TZ) {
  const p = tzParts(date, tz);
  const asUTC = Date.UTC(+p.year, +p.month - 1, +p.day,
                         +p.hour % 24, +p.minute, +p.second);
  return asUTC - Math.floor(date.getTime() / 1000) * 1000;
}

// Today's date where he is, as YYYY-MM-DD.
function bizToday(tz = BIZ_TZ) {
  const p = tzParts(new Date(), tz);
  return `${p.year}-${p.month}-${p.day}`;
}

function addDays(key, n) {
  const [y, m, d] = key.split('-').map(Number);
  const t = new Date(Date.UTC(y, m - 1, d + n));
  return t.toISOString().slice(0, 10);
}

/* The UTC instants that bracket one local day. The offset is probed at local
   midday, which is never inside a changeover, so a day that is 23 or 25 hours
   long still starts and ends in the right place. */
function dayWindow(key, tz = BIZ_TZ) {
  const [y, m, d] = key.split('-').map(Number);
  const off = tzOffsetMs(new Date(Date.UTC(y, m - 1, d, 12)), tz);
  const start = Date.UTC(y, m - 1, d, 0, 0, 0) - off;
  const endOff = tzOffsetMs(new Date(Date.UTC(y, m - 1, d + 1, 12)), tz);
  const end = Date.UTC(y, m - 1, d + 1, 0, 0, 0) - endOff - 1000;
  return { startISO: new Date(start).toISOString(), endISO: new Date(end).toISOString() };
}

/* Which local day an event belongs to. With the Prefer header above, Graph
   returns times already in his zone and says so; without it they are UTC. */
function bizDateOf(dateTime, zone) {
  if (!dateTime) return null;
  const local = zone && !/^utc$/i.test(zone);
  if (local) return String(dateTime).slice(0, 10);
  const t = Date.parse(String(dateTime).endsWith('Z') ? dateTime : dateTime + 'Z');
  if (!Number.isFinite(t)) return null;
  const p = tzParts(new Date(t), BIZ_TZ);
  return `${p.year}-${p.month}-${p.day}`;
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
    // Most of his contacts have two or three numbers on file and RecruiterFlow
    // does not label them, so the map offers the lot rather than guessing which
    // one is the desk and which is the mobile.
    phones: phones.filter(Boolean).slice(0, 4),
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

/* The client companies themselves. Ryan asked whether RecruiterFlow holds
   more firms than the map was showing, and it does: the map was inferring
   firms from the 119 contact records, which can only ever show a company that
   happens to have a person attached, at the city where that person lives.

   /client/list is the real thing — every account on file, with its own
   address, its web domain and its open jobs. So an office with nobody
   attached to it yet still earns a pin, and a firm with an address of its own
   is pinned there rather than wherever its people happen to sit. */
/* Measured against the live account the first time this ran: the client list
   is at least 10,000 records — it hit the 100-page ceiling exactly — of which
   9,737 have an address and 9,600 have nobody attached to them and no open
   roles. It is a bulk-imported list of agencies, not his book. Pinned raw, Los
   Angeles came back with 366 firms against 8 people, which buries the handful
   that matter under everything that doesn't.

   So the client list is used to ENRICH the firms he actually deals with,
   never to populate the map by itself. A firm earns a place if one of his
   contacts works there, if it has a role open, or if he has actually spoken to
   it. Everything else stays off. */
const clientsCache = { data: null, expiry: 0, via: null, scanned: 0 };
let clientsInFlight = null;
const CLIENT_TTL = Number(process.env.CLIENT_TTL_MS || 6 * 3600000);
const CLIENT_MAX_PAGES = Number(process.env.CLIENT_MAX_PAGES || 200);

function clientIsRelevant(f, wantedIds, wantedKeys) {
  if (wantedIds.has(f.id)) return true;
  if (wantedKeys.has(coKey(f.name) || String(f.name || '').toLowerCase())) return true;
  if (f.openJobs > 0) return true;
  return !!(f.lastContact || f.lastEngagement);
}

async function getClients(wantedIds, wantedKeys) {
  if (clientsCache.data && Date.now() < clientsCache.expiry) return clientsCache.data;
  if (clientsInFlight) return clientsInFlight;

  const rfGet = path => fetchJSON({
    hostname: 'recruiterflow.com', path, method: 'GET',
    headers: { 'rf-api-key': CONFIG.recruiterflow.apiKey }
  });

  clientsInFlight = (async () => {
    /* Fast path: ask for the few dozen firms his contacts work at, by id.
       Crawling 100+ pages every refresh to find 45 records is the kind of
       thing that makes a dashboard feel slow for no reason. */
    const ids = [...wantedIds].filter(Boolean).slice(0, 300);
    const byId = [];
    let perId = false;
    if (ids.length) {
      const probe = await rfGet(`/api/external/client/${ids[0]}`);
      const rec = probe.body && (probe.body.data || probe.body);
      if (probe.status === 200 && rec && rec.id) {
        perId = true;
        byId.push(rec);
        for (const id of ids.slice(1)) {
          const r = await rfGet(`/api/external/client/${id}`);
          const b = r.body && (r.body.data || r.body);
          if (r.status === 200 && b && b.id) byId.push(b);
        }
      }
    }

    let all, via, scanned;
    if (perId) {
      all = byId; via = 'by-id'; scanned = byId.length;
    } else {
      // Fall back to the list, and filter it down to what is actually his.
      const raw = [];
      let page = 1;
      while (page <= CLIENT_MAX_PAGES) {
        const res = await rfGet(`/api/external/client/list?current_page=${page}&items_per_page=100`);
        if (res.status !== 200) {
          console.warn(`[clients] client/list returned ${res.status}`);
          break;
        }
        const pageData = Array.isArray(res.body) ? res.body : (res.body?.data || []);
        if (!pageData.length) break;
        raw.push(...pageData);
        if (pageData.length < 100) break;
        page++;
      }
      scanned = raw.length;
      all = raw.filter(c => clientIsRelevant(clientRecord(c), wantedIds, wantedKeys));
      via = 'list';
    }

    console.log(`[clients] ${all.length} firms kept via ${via} (scanned ${scanned})`);
    clientsCache.data = all;
    clientsCache.via = via;
    clientsCache.scanned = scanned;
    clientsCache.expiry = Date.now() + CLIENT_TTL;
    PLACES.builtFor = null;
    return all;
  })().catch(e => {
    // A map missing its client offices still beats no map.
    console.warn('[clients]', e.message);
    clientsCache.data = [];
    clientsCache.via = 'failed';
    clientsCache.expiry = Date.now() + 60000;
    return [];
  }).finally(() => { clientsInFlight = null; });

  return clientsInFlight;
}

function clientRecord(c) {
  const phones = Array.isArray(c.phone_number) ? c.phone_number : (c.phone_number ? [c.phone_number] : []);
  return {
    id: c.id || null,
    name: String(c.name || '').trim(),
    domain: String(c.domain || '').trim().toLowerCase(),
    industry: c.industry || '',
    openJobs: Array.isArray(c.open_jobs) ? c.open_jobs.length : 0,
    phone: phones[0] || '',
    lastContact: c.last_contact || null,
    lastEngagement: c.last_engagement || null,
    geo: geoForLocation(c.location)
  };
}

async function buildPlaces() {
  const contacts = await getContacts();
  /* Which firms are his: the ones his contacts work at. The client list is
     read through this lens rather than wholesale — see getClients(). */
  const wantedIds = new Set();
  const wantedKeys = new Set();
  for (const c of contacts) {
    if (c.client_company_id) wantedIds.add(c.client_company_id);
    const n = String(c.client_company_name || '').trim();
    if (n) wantedKeys.add(coKey(n) || n.toLowerCase());
  }
  const clients = await getClients(wantedIds, wantedKeys);
  if (PLACES.builtFor === contactsCache.expiry) return PLACES;

  const unplaced = [];
  const seeds = new Map();               // lat|lon|precision -> seed

  const seedAt = g => {
    const k = `${g.lat.toFixed(4)}|${g.lon.toFixed(4)}|${g.precision}`;
    let s = seeds.get(k);
    if (!s) seeds.set(k, s = { lat: g.lat, lon: g.lon, city: g.city, state: g.state,
                               precision: g.precision, people: [], firms: [] });
    return s;
  };

  for (const c of contacts) {
    const g = geoForLocation(c.location);
    const p = contactPerson(c);
    if (!p.name) continue;
    if (!g) { unplaced.push(p); continue; }
    p.city = g.city || '';
    p.state = g.state || '';
    seedAt(g).people.push(p);
  }

  // Firms with an address of their own. Those without one are not lost: their
  // people still place them, through the loop above.
  const firmsByKey = new Map();          // coKey -> client record, for enrichment
  let firmsPlaced = 0;
  for (const raw of clients) {
    const f = clientRecord(raw);
    if (!f.name) continue;
    const key = coKey(f.name) || f.name.toLowerCase();
    if (!firmsByKey.has(key)) firmsByKey.set(key, f);
    if (!f.geo) continue;
    seedAt(f.geo).firms.push(f);
    firmsPlaced++;
  }

  /* Merge neighbouring seeds into one pin, biggest first so the anchor is the
     city he is most likely to recognise. A state-centroid seed means "somewhere
     in Illinois" — merging that into Chicago would put a name on a location we
     do not actually have, so precision levels never mix. */
  const ordered = [...seeds.values()]
    .sort((a, b) => (b.people.length + b.firms.length) - (a.people.length + a.firms.length));
  const list = [];
  for (const s of ordered) {
    const host = list.find(l =>
      l.precision === s.precision &&
      l.state === s.state &&
      (s.precision === 'state' ||
       milesBetween(l.lat, l.lon, s.lat, s.lon) <= PLACE_MERGE_MI));
    if (host) {
      host.people.push(...s.people);
      host.firms.push(...s.firms);
      if (s.city && !host.cities.includes(s.city)) host.cities.push(s.city);
    } else {
      list.push({ id: `p${list.length}`, lat: s.lat, lon: s.lon, city: s.city, state: s.state,
                  precision: s.precision, cities: s.city ? [s.city] : [],
                  people: s.people, firms: s.firms });
    }
  }

  for (const l of list) {
    l.companies = consolidateCompanies(l.people);

    /* Two jobs here. A firm with an office at this place and nobody attached
       is still somewhere he can call on, so it earns an entry of its own. And
       a firm that IS represented by people here gets what only the client
       record knows: its domain, and how many roles are open. */
    const byKey = new Map(l.companies.map(co => [coKey(co.name) || co.name.toLowerCase(), co]));
    let officeJobs = 0;                 // roles at an office that is actually HERE
    for (const f of l.firms) {
      const key = coKey(f.name) || f.name.toLowerCase();
      const known = byKey.get(key);
      officeJobs += f.openJobs;
      if (known) {
        known.domain = known.domain || f.domain;
        known.openJobs = f.openJobs;
        known.jobsScope = 'office';
        known.clientId = known.clientId || f.id;
        if (f.name !== known.name && !known.variants.includes(f.name)) known.variants.push(f.name);
      } else {
        l.companies.push(byKey.set(key, {
          name: f.name, variants: [], ids: f.id ? [f.id] : [], people: [],
          domain: f.domain, openJobs: f.openJobs, jobsScope: 'office',
          clientId: f.id, officeOnly: true
        }).get(key));
      }
    }

    /* Anything the client list knows about a firm we only heard of through a
       contact — the domain especially, which is how an attendee with a work
       email address can be placed at all.

       Its open roles come across too, but marked as the firm's total rather
       than this office's. Trucordia has no address of its own and people in
       two cities; adding its four open roles to both would have the book
       showing eight, and each pin claiming four roles in a city that may have
       none of them. */
    for (const co of l.companies) {
      const f = firmsByKey.get(coKey(co.name) || co.name.toLowerCase());
      if (!f) continue;
      co.domain = co.domain || f.domain;
      co.clientId = co.clientId || f.id;
      if (co.jobsScope !== 'office' && f.openJobs) {
        co.openJobs = f.openJobs;
        co.jobsScope = 'firm';
      }
    }

    l.companies.sort((a, b) => b.people.length - a.people.length ||
                               (b.openJobs || 0) - (a.openJobs || 0) ||
                               a.name.localeCompare(b.name));
    l.peopleCount = l.people.length;
    l.companyCount = l.companies.length;
    l.openJobs = officeJobs;
    // The raw lists would duplicate what companies[] already carries.
    delete l.people;
    delete l.firms;
  }
  list.sort((a, b) => (b.peopleCount + b.companyCount) - (a.peopleCount + a.companyCount));

  PLACES.list = list;
  PLACES.unplaced = unplaced;
  PLACES.clients = clients.length;
  PLACES.clientsPlaced = firmsPlaced;
  PLACES.builtFor = contactsCache.expiry;
  console.log(`[places] ${contacts.length} contacts + ${clients.length} clients ` +
              `(${firmsPlaced} with an address) → ${list.length} places, ` +
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

    /* A named date, or a run of days starting today. Without either it answers
       exactly as it always did, so a half-landed deploy cannot break the
       schedule. */
    if (query.date || query.days) {
      const n = Math.min(Math.max(Number(query.days) || 1, 1), 31);
      const first = String(query.date || bizToday());
      const keys = [];
      for (let i = 0; i < n; i++) keys.push(addDays(first, i));

      const win = { start: dayWindow(keys[0]).startISO,
                    end: dayWindow(keys[keys.length - 1]).endISO };
      const res = await fetchJSON({
        hostname: 'graph.microsoft.com',
        path: `/v1.0/users/${process.env.MS_USER_EMAIL}/calendarView` +
              `?startDateTime=${win.start}&endDateTime=${win.end}` +
              `&$select=subject,start,end,bodyPreview,onlineMeeting,attendees,isAllDay` +
              `&$orderby=start/dateTime&$top=400`,
        method: 'GET',
        /* Deliberately NOT asking Graph for local times. The browser has
           assumed throughout that a Graph datetime is UTC — fmtTime appends
           the Z itself — so handing it local wall-clock times showed a 9:30
           meeting at 4:30 in the morning. The day an event belongs to is
           worked out here instead, where the timezone is known. */
        headers: { 'Authorization': `Bearer ${token}` }
      });

      const days = {};
      for (const k of keys) days[k] = [];
      let dropped = 0, allDay = 0;
      for (const e of (res.body?.value || [])) {
        /* All-day items — birthdays, out-of-office, anniversaries — start at
           midnight, so on an arc that maps time of day they pile up at one end
           and say nothing about when he is busy. Counted, not drawn. */
        if (e.isAllDay) { allDay++; continue; }
        const k = bizDateOf(e.start?.dateTime, e.start?.timeZone);
        if (days[k]) days[k].push(e); else dropped++;
      }
      console.log(`[calendar] ${keys.length} day(s) from ${keys[0]}: ` +
                  `${(res.body?.value || []).length} events` +
                  (allDay ? `, ${allDay} all-day skipped` : '') +
                  (dropped ? `, ${dropped} outside the window` : ''));
      return { tz: BIZ_TZ, from: keys[0], to: keys[keys.length - 1], allDay,
               days, counts: Object.fromEntries(keys.map(k => [k, days[k].length])) };
    }

    // Today, in his zone. The boundaries come from dayWindow() now rather than
    // a hardcoded five-hour offset, so they stay right either side of November.
    const today = bizToday();
    const w = dayWindow(today);
    console.log('Fetching calendar for date:', today, w.startISO, '→', w.endISO);
    const res = await fetchJSON({
      hostname: 'graph.microsoft.com',
      path: `/v1.0/users/${process.env.MS_USER_EMAIL}/calendarView?startDateTime=${w.startISO}&endDateTime=${w.endISO}&$select=subject,start,end,bodyPreview,onlineMeeting,attendees&$orderby=start/dateTime&$top=100`,
      method: 'GET',
      headers: { 'Authorization': `Bearer ${token}` }
    });
    console.log('Calendar response status:', res.status, 'items:', res.body?.value?.length);
    return res.body;
  }

  if (pathname === '/api/calendar/tomorrow') {
    const token = await getMSToken();
    const w = dayWindow(addDays(bizToday(), 1));
    const res = await fetchJSON({
      hostname: 'graph.microsoft.com',
      path: `/v1.0/users/${process.env.MS_USER_EMAIL}/calendarView?startDateTime=${w.startISO}&endDateTime=${w.endISO}&$select=subject,start,end,bodyPreview,onlineMeeting,attendees&$orderby=start/dateTime&$top=100`,
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

  /* Does RecruiterFlow expose its Companies object, and under what path?
     The dashboard has only ever read candidates and contacts, so the firms on
     the map are inferred from the 119 contacts — 45 of them. RecruiterFlow's
     own API is documented as covering companies as a first-class object, which
     would mean client offices with no contact attached are invisible to us,
     and that the office address we should be pinning is sitting unused.

     Read-only: GET, three records a page, nothing written. It reports the
     shape rather than the contents, so it can be run safely and the answer
     decides what to build next. */
  if (pathname === '/api/debug/rfpaths') {
    /* Which paths exist, asked with a GET and nothing else — ever. A 405 is
       the useful answer: RecruiterFlow saying "this path is real, wrong
       method", which is exactly how client/search gave itself away. That is
       how the create endpoints get found without POSTing speculatively at a
       live book of business and leaving test people in it.

       `paths` lets a question be asked without another deploy. The method is
       hardcoded and the names are sanitised, so the worst this can do is read
       something that does not exist. */
    const DEFAULTS = [
      'company/list', 'client/list', 'account/list', 'organization/list',
      'companies/list', 'clients/list', 'company/search', 'client/search'
    ];
    const asked = String(query.paths || '')
      .split(',').map(s => s.trim())
      .filter(s => /^[a-z0-9][a-z0-9/_-]{2,48}$/i.test(s))
      .slice(0, 24);
    const paths = asked.length ? asked : DEFAULTS;
    const out = [];
    for (const p of paths) {
      const res = await fetchJSON({
        hostname: 'recruiterflow.com',
        path: `/api/external/${p}?current_page=1&items_per_page=3`,
        method: 'GET',
        headers: { 'rf-api-key': CONFIG.recruiterflow.apiKey }
      }).catch(e => ({ status: 0, body: { error: e.message } }));

      const body = res.body;
      const rows = Array.isArray(body) ? body : (body?.data || body?.value || null);
      out.push({
        path: p,
        status: res.status,
        // 405 means the path is real but wants a POST — the thing we are
        // actually looking for when hunting a create endpoint.
        verdict: res.status === 405 ? 'exists, needs POST'
               : res.status === 200 ? 'exists, readable'
               : res.status === 404 ? 'no such path'
               : `answered ${res.status}`,
        rows: Array.isArray(rows) ? rows.length : null,
        topLevelKeys: (body && !Array.isArray(body)) ? Object.keys(body).slice(0, 12) : null,
        recordKeys: (Array.isArray(rows) && rows[0]) ? Object.keys(rows[0]) : null,
        // Just enough of one record to see whether an address is in there.
        sample: (Array.isArray(rows) && rows[0])
          ? JSON.stringify(rows[0]).slice(0, 700) : null
      });
    }
    let created = null;
    if (query.created) {
      const c = await fetchJSON({ hostname: 'recruiterflow.com', path: '/__created',
        method: 'GET', headers: { 'rf-api-key': CONFIG.recruiterflow.apiKey } }).catch(() => null);
      created = (c && c.body) || null;
    }
    let methods = null;
    if (query.methods) {
      // Used by the test suite to prove this probe never does anything but
      // read. Against the real API the path simply 404s.
      const m = await fetchJSON({ hostname: 'recruiterflow.com', path: '/__rfmethods',
        method: 'GET', headers: { 'rf-api-key': CONFIG.recruiterflow.apiKey } }).catch(() => null);
      methods = (m && m.body) || null;
    }
    return { tried: out.length, results: out, methods, created };
  }

  // The consolidation itself, without a location to centre it on — useful for
  // checking what merged with what.
  if (pathname === '/api/debug/places') {
    const P = await buildPlaces();
    const { list, unplaced } = P;
    return {
      places: list.length,
      unplaced: unplaced.length,
      clients: P.clients,
      clientsWithAnAddress: P.clientsPlaced,
      clientsVia: clientsCache.via,
      clientRecordsScanned: clientsCache.scanned,
      officesWithNobodyAttached: list.reduce((n, l) =>
        n + l.companies.filter(c => c.officeOnly).length, 0),
      openJobs: list.reduce((n, l) => n + (l.openJobs || 0), 0),
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

  /* Can the dashboard ring his phone, or does it have to hand the number to
     the desktop dialer? Answered from the app's own permissions rather than by
     trying it and failing. */
  if (pathname === '/api/call/status') {
    await getRCToken();
    let from = null;
    if (rcCanRingOut()) { try { from = await rcCallerId(); } catch (e) { /* reported below */ } }
    return {
      ringOut: rcCanRingOut() && !!from,
      from,
      scopes: tokens.rcScopes || '',
      reason: rcCanRingOut()
        ? (from ? null : 'no number found to call from — set RC_CALLER_ID')
        : 'the RingCentral app does not have the RingOut permission'
    };
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

  // Is anything he types going to survive the next deploy, and how much is
  // here right now. The browser uses this to decide whether to offer its copy.
  if (pathname === '/api/storage') {
    // This sits in the raw request handler, not handleAPI, so it writes its
    // own response — returning an object here just hangs the request.
    const notes = loadNotes(), overrides = loadOverrides();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      durable: DURABLE,
      where: DURABLE ? DATA_DIR : 'the service filesystem, which is wiped on every deploy',
      notes: Object.keys(notes).length,
      overrides: Object.keys(overrides).length,
      startedAt: new Date(BOOT_AT).toISOString()
    }));
    return;
  }

  /* The browser handing back what the server lost. Only entries the server
     does not already have are taken, and only ones the browser did not record
     as deliberately cleared — otherwise a note he deleted would rise from the
     dead on the next deploy. */
  if (pathname === '/api/restore' && req.method === 'POST') {
    try {
      const body = await readBody(req);
      const notes = loadNotes();
      const overrides = loadOverrides();
      const cleared = new Set(Array.isArray(body.cleared) ? body.cleared : []);
      const added = [];

      for (const [name, rec] of Object.entries(body.notes || {})) {
        if (notes[name] || cleared.has(name)) continue;
        if (!rec || typeof rec.text !== 'string' || !rec.text.trim()) continue;
        notes[name] = { ...rec, restored: new Date().toISOString() };
        added.push(name);
      }
      const addedOverrides = [];
      for (const [name, label] of Object.entries(body.overrides || {})) {
        if (overrides[name] || cleared.has(name)) continue;
        overrides[name] = label;
        addedOverrides.push(name);
      }

      if (added.length) saveNotes(notes);
      if (addedOverrides.length) saveOverrides(overrides);
      if (added.length || addedOverrides.length) {
        console.log(`[restore] took back ${added.length} note(s) and ` +
                    `${addedOverrides.length} label(s) from the browser: ` +
                    [...added, ...addedOverrides].join(', '));
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, notes: added, overrides: addedOverrides }));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  /* Place a call. RingOut rings HIS phone first and connects the other party
     only once he picks up, so nothing dials out on a stray click and he is
     never the one left holding a ringing line. The dashboard asks him to
     confirm before this is ever reached. */
  if (pathname === '/api/call' && req.method === 'POST') {
    try {
      const body = await readBody(req);
      const to = toE164(body.to);
      const who = String(body.name || '').slice(0, 80);
      if (!to) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'a callable number is required', got: body.to || null }));
        return;
      }
      await getRCToken();
      if (!rcCanRingOut()) {
        res.writeHead(409, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'RingOut is not enabled on this RingCentral app',
                                 scopes: tokens.rcScopes || '', fallback: 'tel' }));
        return;
      }
      const from = await rcCallerId();
      if (!from) {
        res.writeHead(409, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'no number to call from', fallback: 'tel' }));
        return;
      }

      const payload = JSON.stringify({
        from: { phoneNumber: from },
        to: { phoneNumber: to },
        playPrompt: false
      });
      const rc = await fetchJSON({
        hostname: 'platform.ringcentral.com',
        path: '/restapi/v1.0/account/~/extension/~/ring-out',
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${await getRCToken()}`,
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload)
        }
      }, payload);

      const ok = rc.status === 200 || rc.status === 201;
      console.log(`[call] ${who || to}: RingOut ${ok ? 'placed' : 'failed ' + rc.status}`);
      res.writeHead(ok ? 200 : 502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(ok
        ? { ok: true, from, to, callId: rc.body?.id || null,
            status: rc.body?.status?.callStatus || 'InProgress' }
        : { error: rc.body?.message || `RingCentral returned ${rc.status}`,
            status: rc.status, fallback: 'tel' }));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message, fallback: 'tel' }));
    }
    return;
  }

  /* File someone who is on the calendar but in neither list. Writes to his
     real CRM, so: he chooses candidate or contact, the duplicate check runs
     first, and it is one request with no retry — a retried create is a second
     person on file. */
  if (pathname === '/api/person/create' && req.method === 'POST') {
    try {
      const body = await readBody(req);
      const name = String(body.name || '').trim();
      const kind = body.kind === 'contact' ? 'contact' : 'candidate';
      if (!name) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'a name is required' }));
        return;
      }

      // Make sure the pools are warm, or the duplicate check is meaningless.
      await getCandidates().catch(() => {});
      if (!contactsCache.data) await getContacts().catch(() => {});

      const existing = findExistingPerson(name, body.email);
      if (existing && !body.anyway) {
        res.writeHead(409, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'already on file', existing }));
        return;
      }

      const parts = name.split(/\s+/);
      const made = await createInRecruiterFlow({
        firstName: body.firstName || parts[0] || '',
        lastName: body.lastName || parts.slice(1).join(' ') || '',
        email: body.email, phone: body.phone, title: body.title,
        company: body.company, city: body.city, state: body.state
      }, kind);

      if (!made.ok) {
        console.warn(`[create] ${name} as ${kind}: ${made.error}`);
        res.writeHead(502, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(made));
        return;
      }

      /* The new person must be findable immediately — he is about to look at
         their card. Dropping the cached pools forces the next lookup to go
         back to RecruiterFlow rather than answering from a list made before
         this person existed. */
      candidatesCache.expiry = 0;
      contactsCache.expiry = 0;
      PLACES.builtFor = null;

      // A note typed before there was anywhere to put it now has a home.
      const notes = loadNotes();
      let noteMoved = null;
      if (notes[name] && notes[name].text) {
        const r = await pushNoteToRecruiterFlow(made.id, notes[name].text, kind);
        noteMoved = r.ok ? 'pushed' : (r.error || `failed ${r.status}`);
        notes[name] = { ...notes[name], id: made.id, kind };
        saveNotes(notes);
      }

      console.log(`[create] ${name} filed as a ${kind}, id ${made.id}` +
                  (noteMoved ? `, note ${noteMoved}` : ''));
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, id: made.id, kind, note: noteMoved }));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  if (pathname === '/api/notes' && req.method === 'POST') {
    try {
      const body = await readBody(req);
      const name = String(body.name || '').trim();
      const text = String(body.text == null ? '' : body.text);
      const id = body.id || null;
      const kind = body.kind === 'contact' ? 'contact' : 'candidate';
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

      const rf = text.trim() ? await pushNoteToRecruiterFlow(id, text, kind)
                             : { attempted: false, reason: 'note cleared' };
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
  console.log(DURABLE
    ? `[storage] notes and labels kept in ${DATA_DIR} — survives deploys`
    : '[storage] notes and labels are on the service filesystem, which Render wipes ' +
      'on every deploy. The browser keeps a copy and offers it back; set DATA_DIR to ' +
      'a mounted disk to make the server side durable too.');
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
