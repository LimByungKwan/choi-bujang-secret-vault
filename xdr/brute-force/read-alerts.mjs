// 보너스 xdr-01 제작 1 · 경보 읽기 (확인용)
// xdr/fixtures/brute-force.json 의 Wazuh 경보에서 시각·출발 주소·계정·규칙 수준·설명만 뽑아 보여 줍니다.
// 원본 경보는 읽기만 하고 고치지 않습니다. decide.mjs 는 이 파일을 불러오지 않습니다.
import { readFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const FIXTURE = join(root, 'xdr', 'fixtures', 'brute-force.json');

// 비밀값처럼 보이는 문자열(비밀번호·토큰·키·JWT·긴 16진수/base64)은 가립니다.
const SECRET_LIKE = [
  /(password|passwd|pwd|secret|token|api[_-]?key|authorization|bearer)\s*[:=]/i,
  /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/,
  /\b[A-Fa-f0-9]{32,}\b/,
  /\b[A-Za-z0-9+/]{40,}={0,2}/,
];

function safe(value) {
  const text = value === undefined || value === null ? '' : String(value);
  return SECRET_LIKE.some((re) => re.test(text)) ? '[가림]' : text;
}

export function extractRows(fixture) {
  const alerts = Array.isArray(fixture?.alerts) ? fixture.alerts : [];
  return alerts.map((alert) => ({
    id: safe(alert?.id),
    time: safe(alert?.timestamp),
    srcip: safe(alert?.data?.srcip),
    user: safe(alert?.data?.srcuser),
    level: Number.isFinite(alert?.rule?.level) ? alert.rule.level : null,
    description: safe(alert?.rule?.description),
  }));
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  const fixture = JSON.parse(await readFile(FIXTURE, 'utf8'));
  const rows = extractRows(fixture);
  for (const r of rows) {
    console.log([r.id, r.time, r.srcip, r.user, `level=${r.level}`, r.description].join(' | '));
  }
  const total = fixture.alerts.length;
  console.log(`경보 ${total}건 · 뽑은 줄 ${rows.length}줄 · ${total === rows.length ? '일치' : '불일치'}`);
  if (total !== rows.length) process.exitCode = 1;
}
