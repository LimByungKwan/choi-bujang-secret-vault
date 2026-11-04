import { randomUUID } from 'node:crypto';
import { createClient } from '@supabase/supabase-js';
import config from '../../aleph.config.json' with { type: 'json' };
import { readCookie, validateCookieRequest } from '../../src/auth-session.mjs';
import { RULE_IDS } from '../../src/decider.mjs';
import { createLoginVerifier } from '../../src/verify-login.mjs';

const ACCESS_COOKIE = '__Secure-aleph_access';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const CREDENTIAL_STATUSES = ['pending', 'approved', 'rejected', 'revoked'];
const RESTORE_OUTCOMES = ['restored', 'no_change', 'conflict', 'not_owned', 'failed', 'rejected'];

function requestHeader(request, name) {
  if (typeof request.headers?.get === 'function') return request.headers.get(name);
  return request.headers?.[name.toLowerCase()] ?? request.headers?.[name] ?? null;
}

function send(response, status, body) {
  return response.status(status).json(body);
}

function adminIds(env) {
  const value = env.DEVICE_APPROVAL_ADMIN_USER_IDS;
  if (typeof value !== 'string' || value.length === 0) return [];
  return value.split(',').map(id => id.trim()).filter(id => UUID.test(id));
}

async function countByValue(supabase, table, column, value) {
  const { count, error } = await supabase.from(table)
    .select(column, { count: 'exact', head: true })
    .eq(column, value);
  if (error || !Number.isSafeInteger(count) || count < 0) {
    throw new Error('OPS_SUMMARY_QUERY_FAILED');
  }
  return count;
}

async function collectCounts(supabase, table, column, values) {
  const entries = await Promise.all(values.map(async value => [
    value,
    await countByValue(supabase, table, column, value),
  ]));
  return Object.fromEntries(entries);
}

export function createOpsSummaryHandler({
  env = process.env,
  createVerifier = createLoginVerifier,
  createSupabase = createClient,
} = {}) {
  let loginVerifier;

  return async function handler(request, response) {
    const requestId = randomUUID();
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('x-request-id', requestId);

    if (request.method !== 'GET') {
      response.setHeader('Allow', 'GET');
      return send(response, 405, { error: 'METHOD_NOT_ALLOWED' });
    }

    const authorization = requestHeader(request, 'authorization');
    const accessToken = authorization ? null : readCookie(request, ACCESS_COOKIE);
    if (!authorization && !accessToken) return send(response, 401, { error: 'UNAUTHORIZED' });
    if (!authorization) {
      const csrfError = validateCookieRequest(request, config);
      if (csrfError) return send(response, 403, { error: csrfError });
    }

    try {
      if (typeof env.SUPABASE_URL !== 'string' || typeof env.SUPABASE_SECRET_KEY !== 'string'
          || !env.SUPABASE_URL || !env.SUPABASE_SECRET_KEY) {
        return send(response, 503, { error: 'OPS_SUMMARY_UNAVAILABLE' });
      }

      const supabase = createSupabase(env.SUPABASE_URL, env.SUPABASE_SECRET_KEY, {
        auth: { autoRefreshToken: false, detectSessionInUrl: false, persistSession: false },
      });
      loginVerifier ??= createVerifier({
        config,
        supabaseSecretKey: env.SUPABASE_SECRET_KEY,
      });
      const identity = await loginVerifier(authorization ?? `Bearer ${accessToken}`);
      if (!identity || identity.kind !== 'student') {
        return send(response, identity ? 403 : 401, {
          error: identity ? 'FORBIDDEN' : 'UNAUTHORIZED',
        });
      }
      if (!adminIds(env).includes(identity.userId)) {
        return send(response, 403, { error: 'FORBIDDEN' });
      }

      const [revocation, outcomes, latestAudit] = await Promise.all([
        collectCounts(
          supabase,
          'device_approval_credentials',
          'status',
          CREDENTIAL_STATUSES,
        ),
        collectCounts(
          supabase,
          'learning_note_restore_audit',
          'outcome',
          RESTORE_OUTCOMES,
        ),
        supabase.from('learning_note_restore_audit')
          .select('created_at')
          .order('created_at', { ascending: false })
          .limit(1)
          .maybeSingle(),
      ]);
      if (latestAudit.error
          || (latestAudit.data !== null
            && (typeof latestAudit.data?.created_at !== 'string'
              || !Number.isFinite(Date.parse(latestAudit.data.created_at))))) {
        throw new Error('OPS_SUMMARY_QUERY_FAILED');
      }

      const commitSha = env.VERCEL_GIT_COMMIT_SHA;
      return send(response, 200, {
        requestId,
        checkedAt: new Date().toISOString(),
        commit: typeof commitSha === 'string' && commitSha.length > 0
          ? commitSha.slice(0, 7)
          : 'unknown',
        sections: {
          decider: { source: 'code_static', rules: RULE_IDS },
          detect: { source: 'not_connected', events: null },
          revocation: { source: 'api_measured', counts: revocation },
          restore: {
            source: 'api_measured',
            outcomes,
            latestAt: latestAudit.data?.created_at ?? null,
          },
        },
      });
    } catch {
      return send(response, 503, { error: 'OPS_SUMMARY_UNAVAILABLE' });
    }
  };
}

export default createOpsSummaryHandler();
