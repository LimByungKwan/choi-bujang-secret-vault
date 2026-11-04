// 보너스 xdr-01 제작 4 · 알림과 차단
// decide.mjs 의 판단 결과를 받아
//  1) block 결과만 ZTNA 판정기에 꽂는 "추가 확인 단계"용 거부 규칙(xdr/brute-force/deny-rules.json)으로 만들고
//  2) block·alert 결과를 xdr/alerts.log 에 한 줄씩 쌓습니다.
// src/decider.mjs 의 기존 규칙(RULE_IDS·decide)은 고치지 않습니다. 이 파일은 판정기 규칙을 대신하지 않고,
// 판정기 앞에 붙일 수 있는 isSourceBlocked() 확인 부품만 내보냅니다.
import { appendFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..', '..');
const FIXTURE = join(root, 'xdr', 'fixtures', 'brute-force.json');
const DENY_RULES = join(here, 'deny-rules.json');
const ALERTS_LOG = join(root, 'xdr', 'alerts.log');

export const RULE_ID = 'xdr_brute_force_block';
export const BLOCK_TTL_MS = 60 * 60 * 1000; // 차단은 근거 경보 시각부터 1시간만 유지

// 문서용 주소 대역(RFC 5737)만 규칙으로 만듭니다. 그 밖의 값은 넣지 않습니다.
const DOC_IP = /^(192\.0\.2|198\.51\.100|203\.0\.113)\.(?:[1-9]|[1-9]\d|1\d\d|2(?:[0-4]\d|5[0-5]))$/;

function srcipOf(alert) {
  const ip = alert?.data?.srcip;
  return typeof ip === 'string' && DOC_IP.test(ip) ? ip : null;
}

// 경보 묶음과 판단 결과로 거부 규칙을 만듭니다.
// 정상 이벤트(record)가 나온 주소, 알림(alert)만 있는 주소는 막지 않습니다.
export function buildDenyRules(alerts, decisions) {
  const normalIps = new Set();
  const blockByIp = new Map();
  alerts.forEach((alert, i) => {
    const ip = srcipOf(alert);
    const d = decisions[i];
    if (!ip || !d) return;
    if (d.action === 'record') normalIps.add(ip);
    if (d.action !== 'block') return;
    const at = Date.parse(alert.timestamp);
    if (!Number.isFinite(at)) return;
    const entry = blockByIp.get(ip) ?? { ip, alertIds: [], reasons: new Set(), lastAt: 0 };
    entry.alertIds.push(alert.id);
    entry.reasons.add(d.reason);
    entry.lastAt = Math.max(entry.lastAt, at);
    blockByIp.set(ip, entry);
  });

  const rules = [];
  const skipped = [];
  for (const entry of blockByIp.values()) {
    if (normalIps.has(entry.ip)) {
      skipped.push({ srcip: entry.ip, alertIds: entry.alertIds, why: 'normal_activity_from_same_source' });
      continue;
    }
    rules.push({
      ruleId: RULE_ID,
      effect: 'deny',
      match: { srcip: entry.ip },
      expiresAt: new Date(entry.lastAt + BLOCK_TTL_MS).toISOString(),
      sourceAlertIds: entry.alertIds,
      reason: [...entry.reasons].join(','),
    });
  }
  return { rules, skipped };
}

// 판정기 앞에 붙이는 확인 부품: 주소가 만료 전 거부 규칙에 걸리면 deny 근거를 돌려줍니다.
export function isSourceBlocked(srcip, atMs, rules) {
  if (typeof srcip !== 'string' || !Number.isFinite(atMs)) return null;
  const hit = rules.find((r) => r.match.srcip === srcip && atMs < Date.parse(r.expiresAt));
  return hit ? { blocked: true, ruleId: hit.ruleId, sourceAlertIds: hit.sourceAlertIds } : null;
}

function logLine(alert, d) {
  return JSON.stringify({
    at: alert.timestamp,
    alertId: alert.id,
    action: d.action,
    confidence: d.confidence,
    reason: d.reason,
    srcip: srcipOf(alert),
    user: typeof alert?.data?.srcuser === 'string' ? alert.data.srcuser : null,
  });
}

export async function respond() {
  const fixture = JSON.parse(await readFile(FIXTURE, 'utf8'));
  const alerts = fixture.alerts;
  const decisions = [];
  for (const alert of alerts) decisions.push(await decide(alert));

  const { rules, skipped } = buildDenyRules(alerts, decisions);
  await writeFile(DENY_RULES, `${JSON.stringify({
    schema: 'aleph.xdr.deny-rules.v1', moduleKey: 'brute-force', rules, skipped,
  }, null, 2)}\n`, 'utf8');

  const lines = alerts
    .map((alert, i) => (decisions[i].action === 'record' ? null : logLine(alert, decisions[i])))
    .filter(Boolean);
  await mkdir(dirname(ALERTS_LOG), { recursive: true });
  if (lines.length) await appendFile(ALERTS_LOG, `${lines.join('\n')}\n`, 'utf8');

  // 시험 경보를 다시 흘려 확인: 경보 시각 기준으로 차단 규칙에 걸리는지 봅니다.
  const replay = { blocked: { block: 0, alert: 0, record: 0 }, passed: { block: 0, alert: 0, record: 0 } };
  alerts.forEach((alert, i) => {
    const hit = isSourceBlocked(srcipOf(alert), Date.parse(alert.timestamp), rules);
    replay[hit ? 'blocked' : 'passed'][decisions[i].action] += 1;
  });
  return { rules, skipped, logged: lines.length, replay };
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  const out = await respond();
  console.log(`거부 규칙 ${out.rules.length}개 · 제외 ${out.skipped.length}개 · alerts.log ${out.logged}줄 추가`);
  console.log(`다시 흘리기: 막힘 ${JSON.stringify(out.replay.blocked)} · 통과 ${JSON.stringify(out.replay.passed)}`);
  if (out.replay.blocked.record > 0 || out.replay.blocked.alert > 0) process.exitCode = 1;
}
