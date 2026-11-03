import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { test } from 'node:test';
import { createNoteBackupManifest } from '../src/note-backup-manifest.mjs';
import { readCompleteBackup } from '../src/note-backup-read.mjs';
import { signNoteBackupManifest } from '../src/note-backup-sign.mjs';
import { saveVerifiedNoteBackup } from '../src/note-backup-store.mjs';
import { createNoteRestoreHandler } from '../api/notes/restore.js';

const userId = '30000000-0000-4000-8000-000000000071';
const otherUserId = '30000000-0000-4000-8000-000000000072';
const noteId = '50000000-0000-4000-8000-000000000071';
const backupVersion = 'synthetic-api-restore-v1';
const title = 'synthetic backup title marker';
const content = 'synthetic backup content marker';
const tokenMarker = 'synthetic-token-marker';

function createMemoryAdapter() {
  const objects = new Map();
  return {
    objects,
    async createIfAbsent(path, bytes) {
      if (objects.has(path)) return false;
      objects.set(path, Buffer.from(bytes));
      return true;
    },
    async read(path) {
      const bytes = objects.get(path);
      return bytes ? Buffer.from(bytes) : undefined;
    },
  };
}

async function createBackupFixture() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const backup = {
    id: noteId,
    owner_id: userId,
    title,
    content,
    backupVersion,
  };
  const keyId = 'synthetic-restore-api-key';
  const manifest = createNoteBackupManifest({ ...backup, keyId });
  const signature = signNoteBackupManifest({ manifest, privateKey });
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
  const storageAdapter = createMemoryAdapter();
  const saved = await saveVerifiedNoteBackup({
    backup,
    manifest,
    signature,
    trustedPublicKeys: [{ keyId, publicKeyPem }],
    storageAdapter,
  });
  assert.equal(saved.saved, true);
  return {
    backup,
    manifest,
    signature,
    storageAdapter,
    trustedPublicKeys: [{ keyId, publicKeyPem }],
  };
}

function createFakeSupabase(notes, { beforeRpc } = {}) {
  const calls = { queries: [], rpc: [], audits: [] };
  const supabase = {
    storage: { from: () => ({}) },
    async rpc(name, args) {
      assert.equal(name, 'restore_learning_note');
      calls.rpc.push({ ...args });
      if (beforeRpc) await beforeRpc(notes, args);
      const current = notes.find(item => item.id === args.p_note_id);
      let outcome;

      if (args.p_expected_state === 'absent') {
        if (!current) {
          notes.push({
            id: args.p_note_id,
            owner_id: args.p_owner_id,
            title: args.p_title,
            content: args.p_content,
          });
          outcome = 'restored';
        } else if (current.owner_id === args.p_owner_id
            && current.title === args.p_title
            && current.content === args.p_content) {
          outcome = 'no_change';
        } else {
          outcome = 'conflict';
        }
      } else if (!current) {
        outcome = 'conflict';
      } else if (current.owner_id !== args.p_owner_id) {
        outcome = 'not_owned';
      } else if (current.title === args.p_title && current.content === args.p_content) {
        outcome = 'no_change';
      } else if (current.title !== args.p_expected_title
          || current.content !== args.p_expected_content) {
        outcome = 'conflict';
      } else {
        current.title = args.p_title;
        current.content = args.p_content;
        outcome = 'restored';
      }

      calls.audits.push({
        operation_id: args.p_operation_id,
        actor_id: args.p_owner_id,
        note_id: args.p_note_id,
        backup_ref: args.p_backup_ref,
        outcome,
      });
      return { data: outcome, error: null };
    },
  };
  supabase.from = table => {
    if (table === 'learning_note_restore_audit') {
      return {
        async insert(row) {
          calls.audits.push(row);
          return { error: null };
        },
      };
    }
    return {
      select(columns) {
        assert.equal(columns, 'id,owner_id,title,content');
        const filters = {};
        const query = {
          eq(field, value) {
            filters[field] = value;
            return query;
          },
          async maybeSingle() {
            calls.queries.push({ ...filters });
            const note = notes.find(item => item.id === filters.id
              && item.owner_id === filters.owner_id);
            return { data: note ? { ...note } : null, error: null };
          },
        };
        return query;
      },
    };
  };
  return { supabase, calls };
}

async function invoke({
  fixture,
  notes = [],
  authorization = 'Bearer synthetic-student-token',
  body = { targetId: noteId, backupVersion },
  identity = { kind: 'student', userId },
  beforeRpc,
  auditFailure = false,
} = {}) {
  const { supabase, calls } = createFakeSupabase(notes, { beforeRpc });
  if (auditFailure) {
    const originalFrom = supabase.from;
    supabase.from = table => {
      if (table === 'learning_note_restore_audit') {
        return { insert: async () => ({ error: new Error(tokenMarker) }) };
      }
      return originalFrom(table);
    };
  }
  const env = {
    SUPABASE_URL: 'https://synthetic.supabase.invalid',
    SUPABASE_SECRET_KEY: 'synthetic-server-key',
    NOTE_BACKUP_BUCKET: 'synthetic-private-bucket',
    NOTE_BACKUP_TRUSTED_PUBLIC_KEYS_JSON: JSON.stringify(fixture?.trustedPublicKeys ?? []),
  };
  const handler = createNoteRestoreHandler({
    env,
    createVerifier: () => async value => (
      value === authorization ? identity : null
    ),
    createSupabaseClient: () => supabase,
    createStorageAdapter: () => fixture.storageAdapter,
  });

  let statusCode;
  let responseBody;
  const headers = new Map();
  await handler({
    method: 'POST',
    headers: authorization ? { authorization } : {},
    body,
  }, {
    setHeader: (name, value) => headers.set(name.toLowerCase(), value),
    status: value => {
      statusCode = value;
      return { json: value => { responseBody = value; } };
    },
  });
  return { statusCode, body: responseBody, headers, calls, notes };
}

function assertResponseIsSanitized(response) {
  const serialized = JSON.stringify(response.body);
  for (const marker of [title, content, tokenMarker, 'BEGIN PRIVATE KEY']) {
    assert.equal(serialized.includes(marker), false);
  }
}

test('restores a deleted note with its original ID and authenticated owner', async () => {
  const fixture = await createBackupFixture();
  const response = await invoke({ fixture });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.body, { status: 'restored' });
  assert.deepEqual(response.notes, [{
    id: noteId,
    owner_id: userId,
    title,
    content,
  }]);
  assert.equal(response.calls.rpc[0].p_expected_state, 'absent');
  assert.equal(response.calls.rpc[0].p_owner_id, userId);
  assert.equal(response.calls.audits[0].outcome, 'restored');
  assertResponseIsSanitized(response);
});

test('leaves a note unchanged when it already matches the verified backup', async () => {
  const fixture = await createBackupFixture();
  const note = { id: noteId, owner_id: userId, title, content };
  const response = await invoke({ fixture, notes: [note] });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.body, { status: 'no_change' });
  assert.equal(response.calls.rpc.length, 1);
  assert.deepEqual(response.notes, [note]);
  assert.equal(response.calls.audits[0].outcome, 'no_change');
});

test('requires explicit approval of both current fields before replacing a changed note', async () => {
  const fixture = await createBackupFixture();
  const note = {
    id: noteId,
    owner_id: userId,
    title: 'currently approved synthetic title',
    content: 'currently approved synthetic content',
  };
  const rejected = await invoke({ fixture, notes: [{ ...note }] });

  assert.equal(rejected.statusCode, 409);
  assert.deepEqual(rejected.body, { error: 'CURRENT_NOTE_APPROVAL_REQUIRED' });
  assert.equal(rejected.calls.rpc.length, 0);

  const restored = await invoke({
    fixture,
    notes: [{ ...note }],
    body: {
      targetId: noteId,
      backupVersion,
      approvedCurrentTitle: note.title,
      approvedCurrentContent: note.content,
    },
  });

  assert.equal(restored.statusCode, 200);
  assert.deepEqual(restored.body, { status: 'restored' });
  assert.deepEqual(restored.notes, [{
    id: noteId,
    owner_id: userId,
    title,
    content,
  }]);
  assert.equal(restored.calls.rpc[0].p_expected_title, note.title);
  assert.equal(restored.calls.rpc[0].p_expected_content, note.content);
  assertResponseIsSanitized(restored);
});

test('rejects stale approval and refuses an ID collision owned by another user', async () => {
  const fixture = await createBackupFixture();
  const current = {
    id: noteId,
    owner_id: userId,
    title: 'current synthetic title',
    content: 'current synthetic content',
  };
  const staleApproval = await invoke({
    fixture,
    notes: [{ ...current }],
    body: {
      targetId: noteId,
      backupVersion,
      approvedCurrentTitle: current.title,
      approvedCurrentContent: 'stale synthetic content',
    },
  });
  assert.equal(staleApproval.statusCode, 409);
  assert.equal(staleApproval.calls.rpc.length, 0);

  const otherOwner = {
    id: noteId,
    owner_id: otherUserId,
    title: 'other synthetic title',
    content: 'other synthetic content',
  };
  const collision = await invoke({ fixture, notes: [otherOwner] });
  assert.equal(collision.statusCode, 409);
  assert.deepEqual(collision.body, { error: 'RESTORE_CONFLICT' });
  assert.deepEqual(collision.notes, [otherOwner]);
  assert.equal(collision.calls.rpc[0].p_expected_state, 'absent');
  assertResponseIsSanitized(collision);
});

test('DB state changed after the read is rejected by the atomic RPC condition', async () => {
  const fixture = await createBackupFixture();
  const note = {
    id: noteId,
    owner_id: userId,
    title: 'approved synthetic title',
    content: 'approved synthetic content',
  };
  const response = await invoke({
    fixture,
    notes: [{ ...note }],
    body: {
      targetId: noteId,
      backupVersion,
      approvedCurrentTitle: note.title,
      approvedCurrentContent: note.content,
    },
    beforeRpc(rows) {
      rows[0].content = 'concurrent synthetic change';
    },
  });

  assert.equal(response.statusCode, 409);
  assert.deepEqual(response.body, { error: 'RESTORE_CONFLICT' });
  assert.equal(response.notes[0].content, 'concurrent synthetic change');
});

test('rejects unauthenticated, non-student, malformed, and untrusted-backup requests', async () => {
  const fixture = await createBackupFixture();
  const unauthenticated = await invoke({ fixture, authorization: null });
  assert.equal(unauthenticated.statusCode, 401);
  assert.equal(unauthenticated.calls.queries.length, 0);

  const judge = await invoke({
    fixture,
    identity: { kind: 'judge', userId },
  });
  assert.equal(judge.statusCode, 403);
  assert.equal(judge.calls.queries.length, 0);

  const extraOwner = await invoke({
    fixture,
    body: { targetId: noteId, backupVersion, owner_id: userId },
  });
  assert.equal(extraOwner.statusCode, 400);
  assert.equal(extraOwner.calls.rpc.length, 0);
  assert.equal(extraOwner.calls.audits[0].outcome, 'rejected');

  const noTrustedKeys = await invoke({
    fixture: { ...fixture, trustedPublicKeys: [] },
  });
  assert.equal(noTrustedKeys.statusCode, 503);
  assert.deepEqual(noTrustedKeys.body, { error: 'RESTORE_SERVICE_NOT_CONFIGURED' });
  assert.equal(noTrustedKeys.calls.rpc.length, 0);
});

test('does not report a preflight failure as successful when its audit write fails', async () => {
  const fixture = await createBackupFixture();
  const response = await invoke({
    fixture,
    body: { targetId: 'invalid-id', backupVersion },
    auditFailure: true,
  });

  assert.equal(response.statusCode, 503);
  assert.deepEqual(response.body, { error: 'RESTORE_AUDIT_UNAVAILABLE' });
  assertResponseIsSanitized(response);
});

test('request and audit output never include backup text or credentials', async () => {
  const fixture = await createBackupFixture();
  const response = await invoke({ fixture });
  const serialized = JSON.stringify({ body: response.body, audits: response.calls.audits });

  assert.equal(serialized.includes(title), false);
  assert.equal(serialized.includes(content), false);
  assert.equal(serialized.includes(tokenMarker), false);
  assert.equal(serialized.includes('synthetic-server-key'), false);
  assert.equal(serialized.includes(fixture.signature), false);

  const verified = await readCompleteBackup({
    targetId: noteId,
    ownerId: userId,
    backupVersion,
    trustedPublicKeys: fixture.trustedPublicKeys,
    storageAdapter: fixture.storageAdapter,
  });
  assert.equal(verified.read, true);
});
