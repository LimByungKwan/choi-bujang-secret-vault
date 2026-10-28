import { randomBytes, timingSafeEqual } from 'node:crypto';
import config from '../aleph.config.json' with { type: 'json' };

const ACCESS_COOKIE = '__Secure-aleph_access';
const REFRESH_COOKIE = '__Secure-aleph_refresh';
const CSRF_COOKIE = '__Secure-aleph_csrf';
const COOKIE_PATH = '/api';
const CSRF_PATTERN = /^[a-f0-9]{64}$/u;
const TOKEN_PATTERN = /^[A-Za-z0-9._~-]{1,8192}$/u;
const REFRESH_MAX_AGE = 60 * 60 * 24 * 30;

class AuthFailure extends Error {
  constructor(status, code) {
    super(code);
    this.status = status;
    this.code = code;
  }
}

function header(request, name) {
  const headers = request.headers;
  if (typeof headers?.get === 'function') return headers.get(name);
  return headers?.[name.toLowerCase()] ?? headers?.[name] ?? null;
}

function appOriginFor(configValue) {
  let url;
  try {
    url = new URL(configValue?.publicAppUrl);
  } catch {
    throw new AuthFailure(503, 'AUTH_SERVICE_NOT_CONFIGURED');
  }
  if (url.protocol !== 'https:' || url.username || url.password || url.port
      || url.pathname !== '/' || url.search || url.hash) {
    throw new AuthFailure(503, 'AUTH_SERVICE_NOT_CONFIGURED');
  }
  return url.origin;
}

export function readCookie(request, name) {
  const cookieHeader = header(request, 'cookie');
  if (typeof cookieHeader !== 'string') return null;
  let value = null;
  for (const part of cookieHeader.split(';')) {
    const separator = part.indexOf('=');
    if (separator < 0 || part.slice(0, separator).trim() !== name) continue;
    if (value !== null) return null;
    value = part.slice(separator + 1).trim();
  }
  return value;
}

function safeCookieToken(request, name) {
  const value = readCookie(request, name);
  return typeof value === 'string' && TOKEN_PATTERN.test(value) ? value : null;
}

function validCsrfToken(value) {
  return typeof value === 'string' && CSRF_PATTERN.test(value);
}

function csrfMatches(request) {
  const cookie = readCookie(request, CSRF_COOKIE);
  const submitted = header(request, 'x-csrf-token');
  if (!validCsrfToken(cookie) || !validCsrfToken(submitted)) return false;
  return timingSafeEqual(Buffer.from(cookie, 'hex'), Buffer.from(submitted, 'hex'));
}

function originMatches(request, appOrigin, requireOrigin) {
  const origin = header(request, 'origin');
  if (origin !== null) return origin === appOrigin;
  if (requireOrigin) return false;
  const fetchSite = header(request, 'sec-fetch-site');
  if (fetchSite !== null) return fetchSite === 'same-origin';
  const referer = header(request, 'referer');
  if (typeof referer !== 'string') return false;
  try {
    return new URL(referer).origin === appOrigin;
  } catch {
    return false;
  }
}

export function validateCookieRequest(request, configValue = config) {
  const appOrigin = appOriginFor(configValue);
  if (!originMatches(request, appOrigin, false)) return 'ORIGIN_NOT_ALLOWED';
  if (!csrfMatches(request)) return 'CSRF_FAILED';
  return null;
}

function cookie(name, value, maxAge) {
  return `${name}=${value}; Path=${COOKIE_PATH}; Max-Age=${maxAge}; Secure; HttpOnly; SameSite=Strict`;
}

function clearCookie(name) {
  return cookie(name, '', 0);
}

function authCookies(session) {
  const accessMaxAge = Math.max(1, Math.min(session.expiresIn, 86400));
  return [
    cookie(ACCESS_COOKIE, session.accessToken, accessMaxAge),
    cookie(REFRESH_COOKIE, session.refreshToken, REFRESH_MAX_AGE),
  ];
}

function clearedAuthCookies() {
  return [clearCookie(ACCESS_COOKIE), clearCookie(REFRESH_COOKIE)];
}

function csrfCookie(token) {
  return cookie(CSRF_COOKIE, token, REFRESH_MAX_AGE);
}

function publicUser(user) {
  return {
    id: user.id,
    ...(typeof user.email === 'string' ? { email: user.email } : {}),
  };
}

function sessionFrom(data) {
  if (!data || typeof data.access_token !== 'string'
      || !TOKEN_PATTERN.test(data.access_token)
      || typeof data.refresh_token !== 'string'
      || !TOKEN_PATTERN.test(data.refresh_token)
      || !Number.isSafeInteger(data.expires_in) || data.expires_in < 1
      || !data.user || typeof data.user.id !== 'string') {
    throw new AuthFailure(502, 'AUTH_UNAVAILABLE');
  }
  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    expiresIn: data.expires_in,
    user: publicUser(data.user),
  };
}

function isAuthFailure(error) {
  return error instanceof AuthFailure;
}

function sendFailure(response, error) {
  if (!isAuthFailure(error)) throw error;
  return response.status(error.status).json({ error: error.code });
}

function setNoStore(response) {
  response.setHeader('Cache-Control', 'no-store');
}

function methodNotAllowed(response, allowed) {
  response.setHeader('Allow', allowed.join(', '));
  return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
}

function validMutation(request, configValue) {
  const origin = header(request, 'origin');
  let expected;
  try {
    expected = appOriginFor(configValue);
  } catch {
    return 'AUTH_SERVICE_NOT_CONFIGURED';
  }
  if (origin !== expected) return 'ORIGIN_NOT_ALLOWED';
  if (!csrfMatches(request)) return 'CSRF_FAILED';
  return null;
}

function authErrorStatus(error) {
  return isAuthFailure(error) ? error.status : 500;
}

function authErrorCode(error) {
  return isAuthFailure(error) ? error.code : 'AUTH_UNAVAILABLE';
}

export function createAuthService({
  env = process.env,
  fetchImpl = globalThis.fetch,
} = {}) {
  const supabaseUrl = env.SUPABASE_URL;
  const publishableKey = env.SUPABASE_PUBLISHABLE_KEY;
  let baseUrl;
  try {
    baseUrl = new URL(supabaseUrl);
  } catch {
    throw new AuthFailure(503, 'AUTH_SERVICE_NOT_CONFIGURED');
  }
  if (baseUrl.protocol !== 'https:' || baseUrl.username || baseUrl.password
      || baseUrl.port || baseUrl.pathname !== '/' || baseUrl.search || baseUrl.hash
      || typeof publishableKey !== 'string' || !publishableKey.trim()
      || publishableKey !== publishableKey.trim() || typeof fetchImpl !== 'function') {
    throw new AuthFailure(503, 'AUTH_SERVICE_NOT_CONFIGURED');
  }

  async function send(path, options = {}) {
    let response;
    try {
      response = await fetchImpl(new URL(path, baseUrl), {
        ...options,
        cache: 'no-store',
        redirect: 'error',
        signal: AbortSignal.timeout(10000),
        headers: {
          apikey: publishableKey,
          ...(options.headers ?? {}),
        },
      });
    } catch {
      throw new AuthFailure(502, 'AUTH_UNAVAILABLE');
    }
    return response;
  }

  async function parseJson(response) {
    try {
      return await response.json();
    } catch {
      throw new AuthFailure(502, 'AUTH_UNAVAILABLE');
    }
  }

  async function tokenRequest(grantType, body) {
    const url = new URL('/auth/v1/token', baseUrl);
    url.searchParams.set('grant_type', grantType);
    const response = await send(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!response.ok) {
      if (response.status === 400 || response.status === 401) {
        if (grantType === 'refresh_token') return null;
        throw new AuthFailure(401, 'INVALID_CREDENTIALS');
      }
      if (response.status === 429) throw new AuthFailure(429, 'AUTH_RATE_LIMITED');
      throw new AuthFailure(502, 'AUTH_UNAVAILABLE');
    }
    return sessionFrom(await parseJson(response));
  }

  return Object.freeze({
    signIn(email, password) {
      return tokenRequest('password', { email, password });
    },
    refresh(refreshToken) {
      return tokenRequest('refresh_token', { refresh_token: refreshToken });
    },
    async getUser(accessToken) {
      const response = await send('/auth/v1/user', {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      if (response.status === 401 || response.status === 403) return null;
      if (!response.ok) throw new AuthFailure(502, 'AUTH_UNAVAILABLE');
      const user = await parseJson(response);
      if (!user || typeof user.id !== 'string') {
        throw new AuthFailure(502, 'AUTH_UNAVAILABLE');
      }
      return publicUser(user);
    },
    async revoke(accessToken) {
      const response = await send('/auth/v1/logout', {
        method: 'POST',
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      if (response.status === 401 || response.status === 403) return false;
      if (!response.ok) throw new AuthFailure(502, 'AUTH_UNAVAILABLE');
      return true;
    },
  });
}

export function createAuthHandlers({
  config: configValue = config,
  env = process.env,
  fetchImpl = globalThis.fetch,
} = {}) {
  let service;
  const getService = () => {
    service ??= createAuthService({ env, fetchImpl });
    return service;
  };

  async function login(request, response) {
    setNoStore(response);
    if (request.method !== 'POST') return methodNotAllowed(response, ['POST']);
    const csrfError = validMutation(request, configValue);
    if (csrfError) {
      const status = csrfError === 'AUTH_SERVICE_NOT_CONFIGURED' ? 503 : 403;
      return response.status(status).json({ error: csrfError });
    }
    const body = request.body;
    if (!body || typeof body !== 'object' || Array.isArray(body)
        || typeof body.email !== 'string' || !body.email.trim() || body.email.length > 320
        || typeof body.password !== 'string' || !body.password || body.password.length > 1024) {
      return response.status(400).json({ error: 'INVALID_LOGIN_REQUEST' });
    }
    try {
      const session = await getService().signIn(body.email.trim(), body.password);
      response.setHeader('Set-Cookie', authCookies(session));
      return response.status(200).json({
        authenticated: true,
        user: session.user,
      });
    } catch (error) {
      return sendFailure(response, error);
    }
  }

  async function session(request, response) {
    setNoStore(response);
    if (request.method !== 'GET') return methodNotAllowed(response, ['GET']);
    let appOrigin;
    try {
      appOrigin = appOriginFor(configValue);
    } catch (error) {
      return sendFailure(response, error);
    }
    if (!originMatches(request, appOrigin, false)) {
      return response.status(403).json({ error: 'ORIGIN_NOT_ALLOWED' });
    }

    let csrfToken = readCookie(request, CSRF_COOKIE);
    const setCookies = [];
    if (!validCsrfToken(csrfToken)) {
      csrfToken = randomBytes(32).toString('hex');
      setCookies.push(csrfCookie(csrfToken));
    }

    const accessToken = safeCookieToken(request, ACCESS_COOKIE);
    const refreshToken = safeCookieToken(request, REFRESH_COOKIE);
    if (!accessToken || !refreshToken) {
      if (accessToken || refreshToken) setCookies.push(...clearedAuthCookies());
      if (setCookies.length) response.setHeader('Set-Cookie', setCookies);
      return response.status(200).json({ authenticated: false, csrfToken });
    }

    try {
      const auth = getService();
      const user = await auth.getUser(accessToken);
      if (user) {
        if (setCookies.length) response.setHeader('Set-Cookie', setCookies);
        return response.status(200).json({ authenticated: true, user, csrfToken });
      }

      const refreshed = await auth.refresh(refreshToken);
      if (!refreshed) {
        response.setHeader('Set-Cookie', [...setCookies, ...clearedAuthCookies()]);
        return response.status(200).json({ authenticated: false, csrfToken });
      }
      response.setHeader('Set-Cookie', [...setCookies, ...authCookies(refreshed)]);
      return response.status(200).json({
        authenticated: true,
        user: refreshed.user,
        csrfToken,
      });
    } catch (error) {
      return sendFailure(response, error);
    }
  }

  async function logout(request, response) {
    setNoStore(response);
    if (request.method !== 'POST') return methodNotAllowed(response, ['POST']);
    const csrfError = validMutation(request, configValue);
    if (csrfError) {
      const status = csrfError === 'AUTH_SERVICE_NOT_CONFIGURED' ? 503 : 403;
      return response.status(status).json({ error: csrfError });
    }

    const accessToken = safeCookieToken(request, ACCESS_COOKIE);
    const refreshToken = safeCookieToken(request, REFRESH_COOKIE);
    try {
      if (accessToken || refreshToken) {
        const auth = getService();
        let token = accessToken;
        let revoked = token ? await auth.revoke(token) : false;
        if (!revoked && refreshToken) {
          const refreshed = await auth.refresh(refreshToken);
          if (refreshed) {
            token = refreshed.accessToken;
            revoked = await auth.revoke(token);
          }
        }
        if (!revoked) {
          response.setHeader('Set-Cookie', clearedAuthCookies());
          return response.status(502).json({ error: 'AUTH_UNAVAILABLE' });
        }
      }
      response.setHeader('Set-Cookie', clearedAuthCookies());
      return response.status(200).json({ authenticated: false });
    } catch (error) {
      response.setHeader('Set-Cookie', clearedAuthCookies());
      return response.status(authErrorStatus(error)).json({ error: authErrorCode(error) });
    }
  }

  return Object.freeze({ login, session, logout });
}

export const authHandlers = createAuthHandlers();
