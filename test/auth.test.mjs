import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { createAuthHandlers } from '../src/auth-session.mjs';

const csrfToken = 'a'.repeat(64);
const accessToken = 'test-access-token';
const refreshToken = 'test-refresh-token';
const refreshedAccessToken = 'test-refreshed-access-token';
const refreshedRefreshToken = 'test-refreshed-refresh-token';
const appOrigin = 'https://student-defense.vercel.app';
const config = { publicAppUrl: `${appOrigin}/` };
const env = {
  SUPABASE_URL: 'https://unit-test.supabase.co',
  SUPABASE_PUBLISHABLE_KEY: 'test-publishable-key',
};

function responseRecorder() {
  const headers = new Map();
  let statusCode;
  let body;
  return {
    headers,
    get statusCode() { return statusCode; },
    get body() { return body; },
    setHeader(name, value) { headers.set(name.toLowerCase(), value); },
    status(value) {
      statusCode = value;
      return { json(valueBody) { body = valueBody; } };
    },
  };
}

async function invoke(handler, { method, headers = {}, body } = {}) {
  const response = responseRecorder();
  await handler({ method, headers, body }, response);
  return response;
}

function csrfHeaders(extra = {}) {
  return {
    origin: appOrigin,
    cookie: `__Secure-aleph_csrf=${csrfToken}`,
    'x-csrf-token': csrfToken,
    ...extra,
  };
}

function sessionResponse(access, refresh, email = 'student@example.test') {
  return new Response(JSON.stringify({
    access_token: access,
    refresh_token: refresh,
    expires_in: 3600,
    user: { id: '30000000-0000-4000-8000-000000000001', email },
  }), { status: 200, headers: { 'content-type': 'application/json' } });
}

test('login stores Supabase tokens only in secure HttpOnly cookies', async () => {
  let requestUrl;
  let requestInit;
  const handlers = createAuthHandlers({
    config,
    env,
    fetchImpl: async (url, init) => {
      requestUrl = new URL(url);
      requestInit = init;
      return sessionResponse(accessToken, refreshToken);
    },
  });
  const password = 'test-password-not-a-secret';
  const result = await invoke(handlers.login, {
    method: 'POST',
    headers: csrfHeaders(),
    body: { email: 'student@example.test', password },
  });

  assert.equal(result.statusCode, 200);
  assert.equal(result.headers.get('cache-control'), 'no-store');
  assert.deepEqual(result.body, {
    authenticated: true,
    user: {
      id: '30000000-0000-4000-8000-000000000001',
      email: 'student@example.test',
    },
  });
  assert.equal(requestUrl.origin, env.SUPABASE_URL);
  assert.equal(requestUrl.pathname, '/auth/v1/token');
  assert.equal(requestUrl.searchParams.get('grant_type'), 'password');
  assert.deepEqual(JSON.parse(requestInit.body), {
    email: 'student@example.test',
    password,
  });
  assert.equal(requestInit.headers.apikey, env.SUPABASE_PUBLISHABLE_KEY);
  assert.equal(requestInit.headers.Authorization, undefined);
  assert.equal(JSON.stringify(result.body).includes(accessToken), false);
  assert.equal(JSON.stringify(result.body).includes(refreshToken), false);
  assert.equal(JSON.stringify(result.body).includes(password), false);

  const cookies = result.headers.get('set-cookie');
  assert.equal(cookies.length, 2);
  for (const value of cookies) {
    assert.match(value, /^__Secure-aleph_(access|refresh)=/u);
    assert.match(value, /; Path=\/api;/u);
    assert.match(value, /; Secure;/u);
    assert.match(value, /; HttpOnly;/u);
    assert.match(value, /; SameSite=Strict$/u);
  }
});

test('login rejects invalid credentials without returning upstream details', async () => {
  const privateError = 'upstream-password-and-token-must-not-leak';
  const handlers = createAuthHandlers({
    config,
    env,
    fetchImpl: async () => new Response(JSON.stringify({
      message: privateError,
      access_token: accessToken,
      refresh_token: refreshToken,
    }), { status: 400 }),
  });
  const result = await invoke(handlers.login, {
    method: 'POST',
    headers: csrfHeaders(),
    body: { email: 'student@example.test', password: 'wrong-password' },
  });

  assert.equal(result.statusCode, 401);
  assert.deepEqual(result.body, { error: 'INVALID_CREDENTIALS' });
  assert.equal(result.headers.get('cache-control'), 'no-store');
  assert.equal(result.headers.has('set-cookie'), false);
  const output = JSON.stringify(result.body);
  assert.equal(output.includes(privateError), false);
  assert.equal(output.includes(accessToken), false);
  assert.equal(output.includes(refreshToken), false);
});

test('session refreshes expired access tokens and never returns either token', async () => {
  const requests = [];
  const handlers = createAuthHandlers({
    config,
    env,
    fetchImpl: async (url, init) => {
      const requestUrl = new URL(url);
      requests.push({ url: requestUrl, init });
      if (requestUrl.pathname === '/auth/v1/user') {
        return new Response('{}', { status: 401 });
      }
      assert.equal(requestUrl.pathname, '/auth/v1/token');
      assert.equal(requestUrl.searchParams.get('grant_type'), 'refresh_token');
      assert.deepEqual(JSON.parse(init.body), { refresh_token: refreshToken });
      return sessionResponse(refreshedAccessToken, refreshedRefreshToken);
    },
  });
  const result = await invoke(handlers.session, {
    method: 'GET',
    headers: {
      origin: appOrigin,
      cookie: `__Secure-aleph_access=${accessToken}; __Secure-aleph_refresh=${refreshToken}; __Secure-aleph_csrf=${csrfToken}`,
    },
  });

  assert.equal(result.statusCode, 200);
  assert.equal(result.headers.get('cache-control'), 'no-store');
  assert.equal(result.body.authenticated, true);
  assert.equal(result.body.csrfToken, csrfToken);
  assert.equal(requests[0].init.headers.Authorization, `Bearer ${accessToken}`);
  const output = JSON.stringify(result.body);
  assert.equal(output.includes(accessToken), false);
  assert.equal(output.includes(refreshToken), false);
  assert.equal(output.includes(refreshedAccessToken), false);
  assert.equal(output.includes(refreshedRefreshToken), false);
  const cookies = result.headers.get('set-cookie');
  assert.equal(cookies.length, 2);
  assert.ok(cookies.some(value => value.startsWith(`__Secure-aleph_access=${refreshedAccessToken};`)));
  assert.ok(cookies.some(value => value.startsWith(`__Secure-aleph_refresh=${refreshedRefreshToken};`)));
});

test('logout revokes the session and expires both auth cookies', async () => {
  let logoutAuthorization;
  const handlers = createAuthHandlers({
    config,
    env,
    fetchImpl: async (url, init) => {
      assert.equal(new URL(url).pathname, '/auth/v1/logout');
      logoutAuthorization = init.headers.Authorization;
      return new Response(null, { status: 204 });
    },
  });
  const result = await invoke(handlers.logout, {
    method: 'POST',
    headers: csrfHeaders({
      cookie: `__Secure-aleph_access=${accessToken}; __Secure-aleph_refresh=${refreshToken}; __Secure-aleph_csrf=${csrfToken}`,
    }),
  });

  assert.equal(result.statusCode, 200);
  assert.equal(result.headers.get('cache-control'), 'no-store');
  assert.deepEqual(result.body, { authenticated: false });
  assert.equal(logoutAuthorization, `Bearer ${accessToken}`);
  const cookies = result.headers.get('set-cookie');
  assert.equal(cookies.length, 2);
  assert.ok(cookies.every(value => value.includes('; Max-Age=0;')));
  assert.ok(cookies.every(value => value.includes('; Secure;')));
  assert.ok(cookies.every(value => value.includes('; HttpOnly;')));
  assert.ok(cookies.every(value => value.endsWith('; SameSite=Strict')));
  assert.equal(JSON.stringify(result.body).includes(accessToken), false);
  assert.equal(JSON.stringify(result.body).includes(refreshToken), false);
});

test('logout reports revocation failure and still expires auth cookies', async () => {
  const requests = [];
  const privateError = 'upstream-token-and-private-details';
  const handlers = createAuthHandlers({
    config,
    env,
    fetchImpl: async (url, init) => {
      const requestUrl = new URL(url);
      requests.push({ path: requestUrl.pathname, init });
      if (requestUrl.pathname === '/auth/v1/logout') {
        return new Response(JSON.stringify({
          message: privateError,
          access_token: accessToken,
          refresh_token: refreshToken,
        }), { status: 403 });
      }
      assert.equal(requestUrl.pathname, '/auth/v1/token');
      assert.equal(requestUrl.searchParams.get('grant_type'), 'refresh_token');
      assert.deepEqual(JSON.parse(init.body), { refresh_token: refreshToken });
      return new Response(JSON.stringify({
        message: privateError,
        access_token: refreshedAccessToken,
        refresh_token: refreshedRefreshToken,
      }), { status: 401 });
    },
  });
  const result = await invoke(handlers.logout, {
    method: 'POST',
    headers: csrfHeaders({
      cookie: `__Secure-aleph_access=${accessToken}; __Secure-aleph_refresh=${refreshToken}; __Secure-aleph_csrf=${csrfToken}`,
    }),
  });

  assert.deepEqual(requests.map(request => request.path), [
    '/auth/v1/logout',
    '/auth/v1/token',
  ]);
  assert.equal(result.statusCode, 502);
  assert.deepEqual(result.body, { error: 'AUTH_UNAVAILABLE' });
  assert.equal(result.headers.get('cache-control'), 'no-store');
  const cookies = result.headers.get('set-cookie');
  assert.equal(cookies.length, 2);
  assert.ok(cookies.every(value => value.includes('; Max-Age=0;')));
  assert.ok(cookies.every(value => value.includes('; Secure;')));
  assert.ok(cookies.every(value => value.includes('; HttpOnly;')));
  assert.ok(cookies.every(value => value.endsWith('; SameSite=Strict')));
  const output = JSON.stringify(result.body);
  assert.equal(output.includes(privateError), false);
  assert.equal(output.includes(accessToken), false);
  assert.equal(output.includes(refreshToken), false);
});

test('login and logout reject cross-origin or missing-CSRF requests before contacting Supabase', async () => {
  let requests = 0;
  const handlers = createAuthHandlers({
    config,
    env,
    fetchImpl: async () => {
      requests += 1;
      return sessionResponse(accessToken, refreshToken);
    },
  });
  const crossOrigin = await invoke(handlers.login, {
    method: 'POST',
    headers: csrfHeaders({ origin: 'https://attacker.example' }),
    body: { email: 'student@example.test', password: 'test-password' },
  });
  const missingCsrf = await invoke(handlers.logout, {
    method: 'POST',
    headers: { origin: appOrigin },
  });

  assert.equal(crossOrigin.statusCode, 403);
  assert.deepEqual(crossOrigin.body, { error: 'ORIGIN_NOT_ALLOWED' });
  assert.equal(missingCsrf.statusCode, 403);
  assert.deepEqual(missingCsrf.body, { error: 'CSRF_FAILED' });
  assert.equal(crossOrigin.headers.get('cache-control'), 'no-store');
  assert.equal(missingCsrf.headers.get('cache-control'), 'no-store');
  assert.equal(requests, 0);
});

test('browser assets use same-origin auth and never contain Supabase keys or session tokens', async () => {
  const html = await readFile(new URL('../public/index.html', import.meta.url), 'utf8');
  const app = await readFile(new URL('../public/app.js', import.meta.url), 'utf8');
  const browserAssets = `${html}\n${app}`;

  assert.match(html, /src="\/app\.js"/u);
  assert.match(app, /\/api\/auth\/login/u);
  assert.match(app, /\/api\/auth\/session/u);
  assert.match(app, /\/api\/auth\/logout/u);
  assert.match(app, /X-CSRF-Token/u);
  assert.match(app, /credentials: 'same-origin'/u);
  assert.match(app, /retryAfterRefresh/u);
  assert.doesNotMatch(browserAssets, /sb_publishable_[A-Za-z0-9_-]+/u);
  assert.doesNotMatch(browserAssets, /SUPABASE_(?:PUBLISHABLE|SECRET)_KEY/u);
  assert.doesNotMatch(browserAssets, /access_token|refresh_token|localStorage|sessionStorage/u);
  assert.doesNotMatch(browserAssets, /createClient|esm\.sh|Authorization/u);
});
