import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const migrationUrl = new URL(
  '../supabase/migrations/20261104210000_restore_audit_summary.sql',
  import.meta.url,
);

test('restore audit summary function is locked down to service_role execution', () => {
  const sql = readFileSync(migrationUrl, 'utf8');

  assert.match(sql, /\bSECURITY\s+DEFINER\b/i);
  assert.match(sql, /\bSET\s+search_path\s*=\s*''/i);
  assert.match(
    sql,
    /\bREVOKE\s+ALL\s+PRIVILEGES\s+ON\s+FUNCTION\s+public\.learning_note_restore_audit_summary\(\)\s+FROM\s+PUBLIC\s*,\s*anon\s*,\s*authenticated\s*;/i,
  );
  const grants = [...sql.matchAll(/\bGRANT\b[^;]*;/giu)].map(([statement]) => statement);
  assert.deepEqual(grants, [
    'GRANT EXECUTE ON FUNCTION public.learning_note_restore_audit_summary() TO service_role;',
  ]);
  assert.doesNotMatch(sql, /\bGRANT\s+(?:SELECT|INSERT|UPDATE|DELETE)\b/i);
  assert.doesNotMatch(
    sql,
    /\b(?:INSERT\s+INTO|UPDATE\s+public\.|DELETE\s+FROM|DROP\b|ALTER\s+TABLE)\b/i,
  );
});
