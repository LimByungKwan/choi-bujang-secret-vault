import { randomUUID } from 'node:crypto';
import { createClient } from '@supabase/supabase-js';
import config from '../../aleph.config.json' with { type: 'json' };
import { readCookie, validateCookieRequest } from '../../src/auth-session.mjs';
import { readCompleteBackup } from '../../src/note-backup-read.mjs';
import { createSupabaseBackupStorageAdapter } from '../../src/supabase-backup-storage.mjs';
import {
  hashFullNote,
  planSignedNoteRestore,
} from '../../src/note-restore-core.mjs';
import { createLoginVerifier } from '../../src/verify-login.mjs';
import { verifyProtectedDeviceAssertion } from '../../src/device-approval-service.mjs';

// Internal student restore endpoint; the official judge route contract remains unconfirmed.
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const ACCESS_COOKIE = '__Secure-aleph_access';
const MAX_TITLE_BYTES = 64 * 1024;
const MAX_CONTENT_BYTES = 16 * 1024 * 1024;

function requestHeader(request, name) {
  if (typeof request.headers?.get === 'function') return request.headers.get(name);
  return request.headers?.[name.toLowerCase()] ?? request.headers?.[name] ?? null;
}

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function send(response, status, body) {
  return response.status(status).json(body);
}

function exactRequestBody(body) {
  if (!isRecord(body)) return false;
  const allowed = new Set([
    'targetId',
    'backupVersion',
    'approvedCurrentTitle',
    'approvedCurrentContent',
  ]);
  if (Object.keys(body).some(key => !allowed.has(key))
      || typeof body.targetId !== 'string'
      || !UUID.test(body.targetId)
      || typeof body.backupVersion !== 'string'
      || body.backupVersion.length === 0
      || body.backupVersion.length > 100
      || Buffer.byteLength(body.backupVersion, 'utf8') > 100) {
    return false;
  }
  const hasApprovedTitle = Object.hasOwn(body, 'approvedCurrentTitle');
  const hasApprovedContent = Object.hasOwn(body, 'approvedCurrentContent');
  if (hasApprovedTitle !== hasApprovedContent) return false;
  return !hasApprovedTitle
    || (typeof body.approvedCurrentTitle === 'string'
      && Buffer.byteLength(body.approvedCurrentTitle, 'utf8') <= MAX_TITLE_BYTES
      && typeof body.approvedCurrentContent === 'string'
      && Buffer.byteLength(body.approvedCurrentContent, 'utf8') <= MAX_CONTENT_BYTES);
}

function trustedKeysFromEnvironment(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 128 * 1024) {
    return null;
  }
  try {
    const keys = JSON.parse(value);
    if (!Array.isArray(keys) || keys.length === 0 || keys.length > 32
        || keys.some(key => !isRecord(key)
          || Object.keys(key).length !== 2
          || typeof key.keyId !== 'string'
          || typeof key.publicKeyPem !== 'string')) {
      return null;
    }
    return keys;
  } catch {
    return null;
  }
}

async function writeAudit(supabase, {
  operationId,
  actorId,
  noteId = null,
  backupRef = null,
  outcome,
}) {
  try {
    const { error } = await supabase.from('learning_note_restore_audit').insert({
      operation_id: operationId,
      actor_id: actorId,
      note_id: noteId,
      backup_ref: backupRef,
      outcome,
    });
    return !error;
  } catch {
    return false;
  }
}

function auditFailureResponse(response, audited, status, error) {
  return audited
    ? send(response, status, { error })
    : send(response, 503, { error: 'RESTORE_AUDIT_UNAVAILABLE' });
}

export function createNoteRestoreHandler({
  env = process.env,
  configValue = config,
  createVerifier = createLoginVerifier,
  createSupabaseClient = createClient,
  createStorageAdapter = createSupabaseBackupStorageAdapter,
  verifyDeviceAssertion = verifyProtectedDeviceAssertion,
} = {}) {
  let loginVerifier;

  return async function handler(request, response) {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('Vary', 'Authorization, Cookie');

    const authorization = requestHeader(request, 'authorization');
    const accessToken = authorization ? null : readCookie(request, ACCESS_COOKIE);
    if (!authorization && !accessToken) {
      return send(response, 401, { error: 'UNAUTHORIZED' });
    }
    if (!authorization) {
      const csrfError = validateCookieRequest(request, configValue);
      if (csrfError) return send(response, 403, { error: csrfError });
    }
    if (request.method !== 'POST') {
      response.setHeader('Allow', 'POST');
      return send(response, 405, { error: 'METHOD_NOT_ALLOWED' });
    }

    const supabaseUrl = env.SUPABASE_URL;
    const secretKey = env.SUPABASE_SECRET_KEY;
    if (typeof supabaseUrl !== 'string' || !supabaseUrl
        || typeof secretKey !== 'string' || !secretKey) {
      return send(response, 503, { error: 'RESTORE_SERVICE_NOT_CONFIGURED' });
    }

    let identity;
    try {
      loginVerifier ??= createVerifier({
        config: configValue,
        supabaseSecretKey: secretKey,
      });
      identity = await loginVerifier(authorization ?? `Bearer ${accessToken}`);
    } catch {
      return send(response, 401, { error: 'UNAUTHORIZED' });
    }
    if (!identity) return send(response, 401, { error: 'UNAUTHORIZED' });
    if (identity.kind !== 'student'
        || typeof identity.userId !== 'string'
        || !UUID.test(identity.userId)) {
      return send(response, 403, { error: 'FORBIDDEN' });
    }

    let supabase;
    try {
      supabase = createSupabaseClient(supabaseUrl, secretKey, {
        auth: {
          autoRefreshToken: false,
          detectSessionInUrl: false,
          persistSession: false,
        },
      });
    } catch {
      return send(response, 503, { error: 'RESTORE_SERVICE_UNAVAILABLE' });
    }

    const operationId = randomUUID();
    const body = request.body;
    const noteId = isRecord(body) && typeof body.targetId === 'string'
      && UUID.test(body.targetId)
      ? body.targetId
      : null;
    let deviceApproved = false;
    try {
      deviceApproved = await verifyDeviceAssertion(request, identity, supabase);
    } catch {
      deviceApproved = false;
    }
    if (!deviceApproved) {
      const audited = await writeAudit(supabase, {
        operationId,
        actorId: identity.userId,
        noteId,
        outcome: 'rejected',
      });
      return auditFailureResponse(response, audited, 403, 'DEVICE_NOT_APPROVED');
    }

    if (!exactRequestBody(body)) {
      const audited = await writeAudit(supabase, {
        operationId,
        actorId: identity.userId,
        noteId,
        outcome: 'rejected',
      });
      return auditFailureResponse(response, audited, 400, 'INVALID_RESTORE_REQUEST');
    }

    const trustedPublicKeys = trustedKeysFromEnvironment(
      env.NOTE_BACKUP_TRUSTED_PUBLIC_KEYS_JSON,
    );
    if (!trustedPublicKeys || typeof env.NOTE_BACKUP_BUCKET !== 'string'
        || !env.NOTE_BACKUP_BUCKET) {
      const audited = await writeAudit(supabase, {
        operationId,
        actorId: identity.userId,
        noteId: body.targetId,
        outcome: 'failed',
      });
      return auditFailureResponse(response, audited, 503, 'RESTORE_SERVICE_NOT_CONFIGURED');
    }

    let storageAdapter;
    try {
      storageAdapter = createStorageAdapter({
        supabaseClient: supabase,
        bucketName: env.NOTE_BACKUP_BUCKET,
      });
    } catch {
      const audited = await writeAudit(supabase, {
        operationId,
        actorId: identity.userId,
        noteId: body.targetId,
        outcome: 'failed',
      });
      return auditFailureResponse(response, audited, 503, 'RESTORE_SERVICE_UNAVAILABLE');
    }

    let backupResult;
    try {
      backupResult = await readCompleteBackup({
        targetId: body.targetId,
        ownerId: identity.userId,
        backupVersion: body.backupVersion,
        trustedPublicKeys,
        storageAdapter,
      });
    } catch {
      backupResult = { read: false };
    }
    if (!backupResult.read) {
      const audited = await writeAudit(supabase, {
        operationId,
        actorId: identity.userId,
        noteId: body.targetId,
        outcome: 'rejected',
      });
      return auditFailureResponse(response, audited, 409, 'BACKUP_UNAVAILABLE');
    }

    let currentResult;
    try {
      currentResult = await supabase
        .from('learning_notes')
        .select('id,owner_id,title,content')
        .eq('id', body.targetId)
        .eq('owner_id', identity.userId)
        .maybeSingle();
    } catch {
      currentResult = { error: true };
    }
    if (!isRecord(currentResult)
        || !Object.hasOwn(currentResult, 'data')
        || currentResult.error
        || (currentResult?.data !== null && currentResult?.data !== undefined
          && (!isRecord(currentResult.data)
            || currentResult.data.id !== body.targetId
            || currentResult.data.owner_id !== identity.userId
            || typeof currentResult.data.title !== 'string'
            || typeof currentResult.data.content !== 'string'))) {
      const audited = await writeAudit(supabase, {
        operationId,
        actorId: identity.userId,
        noteId: body.targetId,
        backupRef: backupResult.backupRef,
        outcome: 'failed',
      });
      return auditFailureResponse(response, audited, 503, 'RESTORE_UNAVAILABLE');
    }

    const currentNote = currentResult.data ?? null;
    const backup = backupResult.backup;
    const matchesBackup = currentNote !== null
      && currentNote.title === backup.title
      && currentNote.content === backup.content;
    const hasApproval = Object.hasOwn(body, 'approvedCurrentTitle');
    if (currentNote && !matchesBackup
        && (!hasApproval
          || body.approvedCurrentTitle !== currentNote.title
          || body.approvedCurrentContent !== currentNote.content)) {
      const audited = await writeAudit(supabase, {
        operationId,
        actorId: identity.userId,
        noteId: body.targetId,
        backupRef: backupResult.backupRef,
        outcome: 'rejected',
      });
      return auditFailureResponse(response, audited, 409, 'CURRENT_NOTE_APPROVAL_REQUIRED');
    }

    let approvedCurrentNoteSha256 = null;
    if (currentNote && !matchesBackup) {
      try {
        approvedCurrentNoteSha256 = hashFullNote({
          ...currentNote,
          backupVersion: body.backupVersion,
        });
      } catch {
        const audited = await writeAudit(supabase, {
          operationId,
          actorId: identity.userId,
          noteId: body.targetId,
          backupRef: backupResult.backupRef,
          outcome: 'rejected',
        });
        return auditFailureResponse(response, audited, 409, 'CURRENT_NOTE_NOT_RESTORABLE');
      }
    }

    const plan = planSignedNoteRestore({
      authenticatedUserId: identity.userId,
      ...backupResult,
      trustedPublicKeys,
      currentNote,
      approvedCurrentNoteSha256,
    });
    if (!plan.integrity.manifestSignatureVerified
        || (!plan.canRestore && plan.reason !== 'already_matches_backup')) {
      const audited = await writeAudit(supabase, {
        operationId,
        actorId: identity.userId,
        noteId: body.targetId,
        backupRef: backupResult.backupRef,
        outcome: 'rejected',
      });
      return auditFailureResponse(response, audited, 409, 'RESTORE_NOT_APPROVED');
    }

    let rpcResult;
    try {
      rpcResult = await supabase.rpc('restore_learning_note', {
        p_operation_id: operationId,
        p_note_id: body.targetId,
        p_owner_id: identity.userId,
        p_title: backup.title,
        p_content: backup.content,
        p_expected_state: currentNote ? 'present' : 'absent',
        p_expected_title: currentNote?.title ?? null,
        p_expected_content: currentNote?.content ?? null,
        p_backup_ref: backupResult.backupRef,
      });
    } catch {
      rpcResult = { error: true };
    }
    if (rpcResult?.error
        || !['restored', 'no_change', 'conflict', 'not_owned', 'failed', 'rejected']
          .includes(rpcResult?.data)) {
      const audited = await writeAudit(supabase, {
        operationId: randomUUID(),
        actorId: identity.userId,
        noteId: body.targetId,
        backupRef: backupResult.backupRef,
        outcome: 'failed',
      });
      return auditFailureResponse(response, audited, 503, 'RESTORE_UNAVAILABLE');
    }

    if (rpcResult.data === 'restored') {
      return send(response, 200, { status: 'restored' });
    }
    if (rpcResult.data === 'no_change') {
      return send(response, 200, { status: 'no_change' });
    }
    if (rpcResult.data === 'failed') {
      return send(response, 503, { error: 'RESTORE_UNAVAILABLE' });
    }
    if (rpcResult.data === 'rejected') {
      return send(response, 400, { error: 'RESTORE_NOT_APPROVED' });
    }
    return send(response, 409, { error: 'RESTORE_CONFLICT' });
  };
}

export default createNoteRestoreHandler();
