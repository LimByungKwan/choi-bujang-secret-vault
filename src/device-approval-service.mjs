import { createClient } from '@supabase/supabase-js';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import config from '../aleph.config.json' with { type: 'json' };
import { readCookie, validateCookieRequest } from './auth-session.mjs';
import { createLoginVerifier } from './verify-login.mjs';
import { createHttpRequestBinding } from '../public/request-binding.mjs';

const ACCESS_COOKIE = '__Secure-aleph_access';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const CREDENTIAL_ID = /^[A-Za-z0-9_-]{1,1024}$/u;
const RP_ID = new URL(config.publicAppUrl).hostname;
const ORIGIN = new URL(config.publicAppUrl).origin;

function header(request, name) {
  if (typeof request.headers?.get === 'function') return request.headers.get(name);
  return request.headers?.[name.toLowerCase()] ?? request.headers?.[name] ?? null;
}

function rawRequestTarget(request) {
  const value = request.url ?? '/api/notes';
  if (typeof value !== 'string') throw new TypeError('invalid_request_target');
  if (value.startsWith('/')) return value;
  const match = /^[A-Za-z][A-Za-z0-9+.-]*:\/\/[^/?#]+(\/[^#]*)?$/u.exec(value);
  if (!match) throw new TypeError('invalid_request_target');
  return match[1] ?? '/';
}

function send(response, status, body) {
  return response.status(status).json(body);
}

function serviceClient(env, createSupabase = createClient) {
  if (!env.SUPABASE_URL || !env.SUPABASE_SECRET_KEY) return null;
  return createSupabase(env.SUPABASE_URL, env.SUPABASE_SECRET_KEY, {
    auth: { autoRefreshToken: false, detectSessionInUrl: false, persistSession: false },
  });
}

function adminIds(env) {
  const value = env.DEVICE_APPROVAL_ADMIN_USER_IDS;
  if (typeof value !== 'string' || value.length === 0) return [];
  return value.split(',').map(id => id.trim()).filter(id => UUID.test(id));
}

async function loadCredential(supabase, ownerId, credentialId) {
  const { data, error } = await supabase.from('device_approval_credentials')
    .select('credential_id,public_key,sign_count,transports,status')
    .eq('owner_id', ownerId)
    .eq('credential_id', credentialId)
    .maybeSingle();
  if (error) throw new Error('DEVICE_APPROVAL_UNAVAILABLE');
  return data;
}

async function loadChallenge(supabase, ownerId, challengeId, purpose) {
  if (!UUID_V4.test(challengeId ?? '')) return null;
  const { data, error } = await supabase.from('device_approval_challenges')
    .select('id,challenge,expires_at,consumed_at,http_method,canonical_target,body_sha256,body_present')
    .eq('id', challengeId)
    .eq('owner_id', ownerId)
    .eq('purpose', purpose)
    .maybeSingle();
  if (error) throw new Error('DEVICE_APPROVAL_UNAVAILABLE');
  if (!data || data.consumed_at || Date.parse(data.expires_at) <= Date.now()) return null;
  return data;
}

async function issueChallenge(supabase, ownerId, purpose, challenge, binding = null) {
  const { data, error } = await supabase.rpc('issue_device_approval_challenge', {
    p_owner_id: ownerId,
    p_purpose: purpose,
    p_challenge: challenge,
    p_expires_at: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
    p_http_method: binding?.method ?? null,
    p_canonical_target: binding?.target ?? null,
    p_body_sha256: binding?.bodySha256 ?? null,
    p_body_present: binding?.bodyPresent ?? null,
  });
  if (error || !UUID_V4.test(data ?? '')) {
    throw new Error('DEVICE_APPROVAL_UNAVAILABLE');
  }
  return data;
}

function parseAssertion(value) {
  if (typeof value !== 'string' || value.length > 32768) return null;
  try {
    const parsed = JSON.parse(value);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)
        || !UUID_V4.test(parsed.challengeId ?? '')
        || !parsed.response || typeof parsed.response !== 'object'
        || Array.isArray(parsed.response)
        || typeof parsed.response.id !== 'string'
        || !CREDENTIAL_ID.test(parsed.response.id)) return null;
    return parsed;
  } catch {
    return null;
  }
}

async function verifyAssertion({
  supabase,
  ownerId,
  purpose,
  assertion,
  verifyResponse = verifyAuthenticationResponse,
  requestBinding = null,
}) {
  const challenge = await loadChallenge(supabase, ownerId, assertion.challengeId, purpose);
  if (!challenge) return { status: 'invalid_challenge' };
  const credential = await loadCredential(supabase, ownerId, assertion.response.id);
  if (!credential) return { status: 'unknown' };

  let verification;
  try {
    verification = await verifyResponse({
      response: assertion.response,
      expectedChallenge: challenge.challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      requireUserVerification: true,
      credential: {
        id: credential.credential_id,
        publicKey: Buffer.from(credential.public_key, 'base64url'),
        counter: Number(credential.sign_count),
        transports: credential.transports,
      },
    });
  } catch {
    return { status: 'invalid_assertion' };
  }
  if (!verification.verified) return { status: 'invalid_assertion' };

  const storedBinding = {
    method: challenge.http_method,
    target: challenge.canonical_target,
    bodySha256: challenge.body_sha256,
    bodyPresent: challenge.body_present,
  };
  if (purpose === 'notes'
      && (!requestBinding
        || storedBinding.method !== requestBinding.method
        || storedBinding.target !== requestBinding.target
        || storedBinding.bodySha256 !== requestBinding.bodySha256
        || storedBinding.bodyPresent !== requestBinding.bodyPresent)) {
    return { status: 'request_mismatch' };
  }
  if (purpose !== 'notes'
      && (storedBinding.method !== null || storedBinding.target !== null
        || storedBinding.bodySha256 !== null || storedBinding.bodyPresent !== null)) {
    return { status: 'request_mismatch' };
  }

  const { data, error } = await supabase.rpc('consume_device_assertion', {
    p_challenge_id: challenge.id,
    p_owner_id: ownerId,
    p_challenge: challenge.challenge,
    p_credential_id: credential.credential_id,
    p_sign_count: verification.authenticationInfo.newCounter,
    p_http_method: requestBinding?.method ?? null,
    p_canonical_target: requestBinding?.target ?? null,
    p_body_sha256: requestBinding?.bodySha256 ?? null,
    p_body_present: requestBinding?.bodyPresent ?? null,
  });
  if (error) throw new Error('DEVICE_APPROVAL_UNAVAILABLE');
  return { status: data };
}

export async function verifyProtectedDeviceAssertion(
  request,
  identity,
  supabase,
  verifyResponse = verifyAuthenticationResponse,
) {
  const assertion = parseAssertion(header(request, 'x-device-assertion'));
  if (!assertion || identity?.kind !== 'student' || !UUID.test(identity.userId ?? '')) {
    return false;
  }
  try {
    const requestBinding = await createHttpRequestBinding({
      method: request.method,
      target: rawRequestTarget(request),
      body: request.body,
      hasBody: request.body !== undefined,
    });
    const result = await verifyAssertion({
      supabase,
      ownerId: identity.userId,
      purpose: 'notes',
      assertion,
      verifyResponse,
      requestBinding,
    });
    return result.status === 'approved';
  } catch {
    return false;
  }
}

export function createDeviceApprovalHandler({
  env = process.env,
  createVerifier = createLoginVerifier,
  verifyRegistration = verifyRegistrationResponse,
  makeRegistrationOptions = generateRegistrationOptions,
  makeAuthenticationOptions = generateAuthenticationOptions,
  verifyAssertionResponse = verifyAuthenticationResponse,
  createSupabase = createClient,
} = {}) {
  let loginVerifier;
  return async function handler(request, response) {
    response.setHeader('Cache-Control', 'no-store');
    const authorization = header(request, 'authorization');
    const accessToken = authorization ? null : readCookie(request, ACCESS_COOKIE);
    if (!authorization && !accessToken) return send(response, 401, { error: 'UNAUTHORIZED' });
    if (!authorization) {
      const csrfError = validateCookieRequest(request, config);
      if (csrfError) return send(response, 403, { error: csrfError });
    }

    let identity;
    try {
      const supabase = serviceClient(env, createSupabase);
      if (!supabase) return send(response, 503, { error: 'DEVICE_APPROVAL_UNAVAILABLE' });
      loginVerifier ??= createVerifier({ config, supabaseSecretKey: env.SUPABASE_SECRET_KEY });
      identity = await loginVerifier(authorization ?? `Bearer ${accessToken}`);
      if (!identity || identity.kind !== 'student') {
        return send(response, identity ? 403 : 401, { error: identity ? 'FORBIDDEN' : 'UNAUTHORIZED' });
      }

      const path = new URL(request.url ?? '/api/device', ORIGIN).pathname;
      const action = path.slice('/api/device/'.length);
      const allowedMethods = action === 'admin' ? ['GET', 'POST'] : ['POST'];
      if (!allowedMethods.includes(request.method)) {
        response.setHeader('Allow', allowedMethods.join(', '));
        return send(response, 405, { error: 'METHOD_NOT_ALLOWED' });
      }

      if (action === 'registration-options') {
        const { data: existing, error: existingError } = await supabase
          .from('device_approval_credentials').select('credential_id')
          .eq('owner_id', identity.userId);
        if (existingError) throw new Error('DEVICE_APPROVAL_UNAVAILABLE');
        const options = await makeRegistrationOptions({
          rpName: 'BYTE BACK 자료실',
          rpID: RP_ID,
          userID: Buffer.from(identity.userId),
          userName: identity.userId,
          attestationType: 'none',
          excludeCredentials: (existing ?? []).map(item => ({ id: item.credential_id })),
          authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
        });
        const id = await issueChallenge(
          supabase, identity.userId, 'registration', options.challenge,
        );
        return send(response, 200, { challengeId: id, options });
      }

      if (action === 'registration-verify') {
        const { challengeId, response: credentialResponse } = request.body ?? {};
        const challenge = await loadChallenge(supabase, identity.userId, challengeId, 'registration');
        if (!challenge || !credentialResponse || typeof credentialResponse !== 'object') {
          return send(response, 400, { error: 'INVALID_REGISTRATION' });
        }
        let result;
        try {
          result = await verifyRegistration({
            response: credentialResponse,
            expectedChallenge: challenge.challenge,
            expectedOrigin: ORIGIN,
            expectedRPID: RP_ID,
            requireUserVerification: true,
          });
        } catch {
          return send(response, 400, { error: 'INVALID_REGISTRATION' });
        }
        const credential = result.registrationInfo?.credential;
        const transports = credential?.transports ?? [];
        if (!result.verified || !credential
            || !CREDENTIAL_ID.test(credential.id)
            || !Number.isSafeInteger(credential.counter) || credential.counter < 0
            || !Array.isArray(transports)
            || !transports.every(transport => (
              ['ble', 'hybrid', 'internal', 'nfc', 'smart-card', 'usb'].includes(transport)
            ))) {
          return send(response, 400, { error: 'INVALID_REGISTRATION' });
        }
        const { data, error } = await supabase.rpc('complete_device_registration', {
          p_challenge_id: challenge.id,
          p_owner_id: identity.userId,
          p_challenge: challenge.challenge,
          p_credential_id: credential.id,
          p_public_key: Buffer.from(credential.publicKey).toString('base64url'),
          p_sign_count: credential.counter,
          p_transports: transports,
        });
        if (error) throw new Error('DEVICE_APPROVAL_UNAVAILABLE');
        if (data !== 'pending') return send(response, 409, { error: 'REGISTRATION_CONFLICT' });
        return send(response, 201, { status: 'pending' });
      }

      if (action === 'challenge') {
        const purpose = request.body?.purpose;
        if (!['status', 'notes'].includes(purpose)) {
          return send(response, 400, { error: 'INVALID_PURPOSE' });
        }
        let binding = null;
        if (purpose === 'notes') {
          try {
            binding = await createHttpRequestBinding({
              method: request.body?.method,
              target: request.body?.target,
              body: request.body?.body,
              hasBody: request.body?.hasBody,
            });
          } catch {
            return send(response, 400, { error: 'INVALID_REQUEST_BINDING' });
          }
          const targetUrl = new URL(binding.target, ORIGIN);
          const validRoute = (
            targetUrl.pathname === '/api/notes'
              && ['GET', 'POST'].includes(binding.method)
          ) || (
            /^\/api\/notes\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu
              .test(targetUrl.pathname)
              && ['GET', 'PUT', 'DELETE'].includes(binding.method)
          ) || (
            targetUrl.pathname === '/api/notes/restore'
              && binding.method === 'POST'
          );
          if (!validRoute) return send(response, 400, { error: 'INVALID_REQUEST_BINDING' });
        }
        const statusFilter = purpose === 'notes' ? ['approved'] : ['pending', 'approved'];
        const { data: credentials, error: credentialError } = await supabase
          .from('device_approval_credentials')
          .select('credential_id,transports')
          .eq('owner_id', identity.userId)
          .in('status', statusFilter);
        if (credentialError) throw new Error('DEVICE_APPROVAL_UNAVAILABLE');
        if (!credentials?.length) return send(response, 200, { status: 'unapproved' });
        const options = await makeAuthenticationOptions({
          rpID: RP_ID,
          allowCredentials: credentials.map(item => ({
            id: item.credential_id, transports: item.transports,
          })),
          userVerification: 'required',
        });
        const id = await issueChallenge(supabase, identity.userId, purpose, options.challenge, binding);
        return send(response, 200, { challengeId: id, options });
      }

      if (action === 'verify') {
        const assertion = parseAssertion(JSON.stringify(request.body ?? {}));
        if (!assertion) return send(response, 400, { error: 'INVALID_ASSERTION' });
        const result = await verifyAssertion({
          supabase, ownerId: identity.userId,
          purpose: request.body.purpose,
          assertion,
          verifyResponse: verifyAssertionResponse,
        });
        return send(response, 200, { status: result.status });
      }

      if (action === 'admin') {
        if (!adminIds(env).includes(identity.userId)) {
          return send(response, 403, { error: 'FORBIDDEN' });
        }
        if (request.method === 'GET') {
          const { data, error } = await supabase
            .from('device_approval_credentials')
            .select('credential_id,owner_id,status,created_at')
            .eq('status', 'pending')
            .order('created_at', { ascending: true });
          if (error) throw new Error('DEVICE_APPROVAL_UNAVAILABLE');
          return send(response, 200, { requests: data ?? [] });
        }
        const { credentialId, ownerId, decision } = request.body ?? {};
        if (!CREDENTIAL_ID.test(credentialId ?? '') || !UUID.test(ownerId ?? '')
            || !['approve', 'reject', 'revoke'].includes(decision)) {
          return send(response, 400, { error: 'INVALID_DECISION' });
        }
        const { data, error } = await supabase.rpc('decide_device_approval', {
          p_credential_id: credentialId,
          p_owner_id: ownerId,
          p_admin_id: identity.userId,
          p_action: decision,
        });
        if (error) throw new Error('DEVICE_APPROVAL_UNAVAILABLE');
        if (data === 'not_found') return send(response, 404, { error: 'DEVICE_NOT_FOUND' });
        if (!['approved', 'rejected', 'revoked'].includes(data)) {
          return send(response, 409, { error: 'DEVICE_DECISION_CONFLICT' });
        }
        return send(response, 200, { status: data });
      }

      return send(response, 404, { error: 'NOT_FOUND' });
    } catch {
      return send(response, 503, { error: 'DEVICE_APPROVAL_UNAVAILABLE' });
    }
  };
}
