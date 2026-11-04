import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { test } from "node:test";

const migrationsDir = new URL("../supabase/migrations/", import.meta.url);
const fixMigrationName = "20261104140500_fix_device_challenge_regex.sql";
const POSTGRES_REGEX_REPEAT_LIMIT = 255;

test("모든 마이그레이션의 정규식 반복 횟수는 PostgreSQL 상한 255 이하다", () => {
  const files = readdirSync(migrationsDir).filter((name) => name.endsWith(".sql"));
  assert.ok(files.length > 0, "검사할 마이그레이션이 있어야 합니다");

  const tooLarge = [];
  for (const name of files) {
    const sql = readFileSync(new URL(name, migrationsDir), "utf8");
    for (const match of sql.matchAll(/\{(\d+)(?:,(\d*))?\}/g)) {
      const bounds = [match[1], match[2]].filter(Boolean).map(Number);
      if (bounds.some((bound) => bound > POSTGRES_REGEX_REPEAT_LIMIT)) {
        tooLarge.push(`${name}: ${match[0]}`);
      }
    }
  }
  assert.deepEqual(tooLarge, []);
});

test("수정 마이그레이션은 챌린지 함수만 교체하고 위험한 문장이 없다", () => {
  const sql = readFileSync(new URL(fixMigrationName, migrationsDir), "utf8");

  assert.ok(sql.includes("CREATE OR REPLACE FUNCTION public.issue_device_approval_challenge("));
  assert.ok(sql.includes("^[A-Za-z0-9_-]{20,255}$"));
  assert.doesNotMatch(sql, /\b(DROP|TRUNCATE|ALTER\s+TABLE|GRANT|REVOKE)\b/i);
});
