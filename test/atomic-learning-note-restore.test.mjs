import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

const migration = await readFile(new URL(
  '../supabase/migrations/20261103174000_atomic_learning_note_restore.sql',
  import.meta.url,
), 'utf8');

test('restore migration uses only columns in the existing learning_notes schema', () => {
  assert.match(migration, /INSERT INTO public\.learning_notes \(id, owner_id, title, content\)/u);
  assert.match(migration, /SET title = p_title, content = p_content/u);
  assert.doesNotMatch(migration, /\b(?:deleted_at|updated_at|restore_version)\b/iu);
});

test('deleted-note restoration inserts the original ID and never updates on conflict', () => {
  assert.match(migration, /VALUES \(p_note_id, p_owner_id, p_title, p_content\)\s+ON CONFLICT \(id\) DO NOTHING/u);
  assert.match(migration, /IF affected_id IS NOT NULL THEN\s+restore_outcome := 'restored'/u);
  assert.doesNotMatch(migration, /ON CONFLICT\s*\(id\)\s*DO UPDATE/iu);
});

test('existing-note writes lock and atomically compare owner, title, and content', () => {
  assert.match(migration, /WHERE id = p_note_id\s+FOR UPDATE/u);
  assert.match(migration, /current_owner_id IS DISTINCT FROM p_owner_id/u);
  assert.match(migration, /current_title IS DISTINCT FROM p_expected_title/u);
  assert.match(migration, /current_content IS DISTINCT FROM p_expected_content/u);
  assert.match(migration, /AND title IS NOT DISTINCT FROM p_expected_title\s+AND content IS NOT DISTINCT FROM p_expected_content/u);
});

test('only service_role can invoke the RPC and audit rows exclude note text', () => {
  assert.match(migration, /SECURITY INVOKER/u);
  assert.match(migration, /SET search_path = pg_catalog, public/u);
  assert.match(migration, /FROM PUBLIC, anon, authenticated/u);
  assert.match(migration, /TO service_role/u);
  assert.match(migration, /learning_note_restore_audit \([\s\S]*?actor_id uuid NOT NULL,[\s\S]*?note_id uuid,[\s\S]*?backup_ref text,[\s\S]*?outcome text NOT NULL/u);
  assert.doesNotMatch(migration, /audit[\s\S]{0,300}\b(?:title|content)\b/iu);
  assert.doesNotMatch(migration, /GRANT\s+DELETE\s+ON\s+TABLE\s+public\.learning_notes/iu);
});
