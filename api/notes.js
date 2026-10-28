import { randomUUID } from 'node:crypto';
import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };
import { readCookie, validateCookieRequest } from '../src/auth-session.mjs';
import { createLoginVerifier } from '../src/verify-login.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const ACCESS_COOKIE = '__Secure-aleph_access';

function requestHeader(request, name) {
  if (typeof request.headers?.get === 'function') return request.headers.get(name);
  return request.headers?.[name.toLowerCase()] ?? request.headers?.[name] ?? null;
}

function logSupabaseFailure(error, status) {
  const code = typeof error?.code === 'string' && /^[A-Za-z0-9_-]{1,32}$/u.test(error.code)
    ? error.code
    : 'UNKNOWN';
  const httpStatus = Number.isInteger(error?.status) ? error.status : status;
  console.error('Supabase notes query failed', {
    code,
    status: Number.isInteger(httpStatus) && httpStatus >= 100 && httpStatus <= 599
      ? httpStatus
      : null,
  });
}

function noteIdFromRequest(request) {
  if (request.query && Object.hasOwn(request.query, 'id')) {
    return { single: true, id: Array.isArray(request.query.id) ? null : request.query.id };
  }

  const pathname = new URL(request.url ?? '/', 'http://localhost').pathname;
  const match = /^\/api\/notes\/([^/]+)\/?$/u.exec(pathname);
  if (!match) return { single: false };

  try {
    return { single: true, id: decodeURIComponent(match[1]) };
  } catch {
    return { single: true, id: null };
  }
}

function validNoteInput(body) {
  return body !== null && typeof body === 'object' && !Array.isArray(body)
    && typeof body.title === 'string' && typeof body.body === 'string';
}

function presentNote(note) {
  return { id: note.id, title: note.title, body: note.content };
}

export function createNotesHandler({ createVerifier = createLoginVerifier } = {}) {
  let loginVerifier;

  return async function handler(request, response) {
    response.setHeader('Cache-Control', 'no-store');

    const authorization = requestHeader(request, 'authorization');
    const accessToken = authorization ? null : readCookie(request, ACCESS_COOKIE);
    if (!authorization && !accessToken) {
      return response.status(401).json({ error: 'UNAUTHORIZED' });
    }
    if (!authorization) {
      const csrfError = validateCookieRequest(request, config);
      if (csrfError) return response.status(403).json({ error: csrfError });
    }

    const supabaseUrl = process.env.SUPABASE_URL;
    const secretKey = process.env.SUPABASE_SECRET_KEY;
    if (!supabaseUrl || !secretKey) {
      return response.status(503).json({ error: 'NOTES_SERVICE_NOT_CONFIGURED' });
    }

    let identity;
    try {
      loginVerifier ??= createVerifier({ config, supabaseSecretKey: secretKey });
      identity = await loginVerifier(authorization ?? `Bearer ${accessToken}`);
    } catch (error) {
      logSupabaseFailure(error);
      return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
    }
    if (!identity) {
      return response.status(401).json({ error: 'UNAUTHORIZED' });
    }
    if (identity.kind !== 'student') {
      return response.status(403).json({ error: 'FORBIDDEN' });
    }

    const route = noteIdFromRequest(request);
    const allowedMethods = route.single
      ? ['GET', 'PUT', 'DELETE']
      : ['GET', 'POST'];
    if (!allowedMethods.includes(request.method)) {
      response.setHeader('Allow', allowedMethods.join(', '));
      return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
    }
    if (route.single && (typeof route.id !== 'string' || !UUID.test(route.id))) {
      return response.status(400).json({ error: 'INVALID_NOTE_ID' });
    }

    try {
      const supabase = createClient(supabaseUrl, secretKey, {
        auth: { autoRefreshToken: false, detectSessionInUrl: false, persistSession: false },
      });

      if (request.method === 'GET' && !route.single) {
        const { data, error, status } = await supabase
          .from('learning_notes')
          .select('id,title,content')
          .eq('owner_id', identity.userId)
          .order('created_at', { ascending: true });
        if (error) {
          logSupabaseFailure(error, status);
          return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
        }
        if (!Array.isArray(data)) {
          logSupabaseFailure(null, status);
          return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
        }
        return response.status(200).json({ notes: data.map(presentNote) });
      }

      if (request.method === 'GET') {
        const { data, error, status } = await supabase
          .from('learning_notes')
          .select('id,title,content')
          .eq('id', route.id)
          .eq('owner_id', identity.userId)
          .maybeSingle();
        if (error) {
          logSupabaseFailure(error, status);
          return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
        }
        if (!data) return response.status(404).json({ error: 'NOTE_NOT_FOUND' });
        return response.status(200).json(presentNote(data));
      }

      if (request.method === 'POST') {
        if (!validNoteInput(request.body)
            || (request.body.id !== undefined
              && (typeof request.body.id !== 'string' || !UUID.test(request.body.id)))) {
          return response.status(400).json({ error: 'INVALID_NOTE' });
        }
        const id = request.body.id ?? randomUUID();
        const { data, error, status } = await supabase
          .from('learning_notes')
          .insert({
            id,
            owner_id: identity.userId,
            title: request.body.title,
            content: request.body.body,
          })
          .select('id')
          .single();
        if (error) {
          logSupabaseFailure(error, status);
          return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
        }
        if (data?.id !== id) {
          logSupabaseFailure(null, status);
          return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
        }
        return response.status(201).json({ id });
      }

      if (request.method === 'PUT') {
        if (!validNoteInput(request.body)) {
          return response.status(400).json({ error: 'INVALID_NOTE' });
        }
        const { data, error, status } = await supabase
          .from('learning_notes')
          .update({ title: request.body.title, content: request.body.body })
          .eq('id', route.id)
          .eq('owner_id', identity.userId)
          .select('id,title,content')
          .maybeSingle();
        if (error) {
          logSupabaseFailure(error, status);
          return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
        }
        if (!data) return response.status(404).json({ error: 'NOTE_NOT_FOUND' });
        return response.status(200).json(presentNote(data));
      }

      const { data, error, status } = await supabase
        .from('learning_notes')
        .delete()
        .eq('id', route.id)
        .eq('owner_id', identity.userId)
        .select('id')
        .maybeSingle();
      if (error) {
        logSupabaseFailure(error, status);
        return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
      }
      if (!data) return response.status(404).json({ error: 'NOTE_NOT_FOUND' });
      return response.status(200).json({ id: data.id });
    } catch (error) {
      logSupabaseFailure(error);
      return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
    }
  };
}

export default createNotesHandler();
