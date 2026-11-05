// 보너스 xdr-04 제작 4 · 알림과 차단 (persistence)
//  1) decide 결과 가운데 block(차단 후보)만 ZTNA 판정기에 꽂는 "추가 확인 단계"용 거부 규칙
//     (xdr/persistence/deny-rules.json)으로 만듭니다. 규칙마다 만료 시각과 근거 경보 번호를 붙입니다.
//  2) 정상 이벤트(record)가 나온 출발 주소는 거부 규칙에서 빼서 정상 사용자를 막지 않습니다.
//  3) block·alert 결과를 xdr/alerts.log 에 한 줄씩 쌓습니다.
// 모든 경보가 같은 PC 이고 같은 계정이 정상 경보에도 나오므로, 규칙은 출발 주소(srcip)로만 만듭니다.
// decide.mjs 는 판단만 하고, 판정기(src/decider.mjs)의 기존 규칙은 고치지 않습니다.
import { appendFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..', '..');
const FIXTURE = join(root, 'xdr', 'fixtures', 'persistence.json');
const DENY_RULES = join(here, 'deny-rules.json');
const ALERTS_LOG = join(root, 'xdr', 'alerts.log');

export const RULE_ID = 'xdr_persistence_block';
export const BLOCK_TTL_MS = 60 * 60 * 1000;

// 문서용 대역 주소만 규칙으로 만듭니다.
const DOC_IP = /^(192\.0\.2|198\.51\.100|203\.0\.113)\.(?:[1-9]|[1-9]\d|1\d\d|2(?:[0-4]\d|5[0-5]))$/u;
const ALERT_ID = /^[a-z0-9][a-z0-9_.-]{0,79}$/iu;

function sourceIp(alert) {
  const value = alert?.data?.srcip;
  return typeof value === 'string' && DOC_IP.test(value) ? value : null;
}

function safeAlertId(alert) {
  return typeof alert?.id === 'string' && ALERT_ID.test(alert.id) ? alert.id : null;
}

export function buildDenyRules(alerts, decisions) {
  const recordIps = new Set();
  const blockByIp = new Map();
  alerts.forEach((alert, index) => {
    const ip = sourceIp(alert);
    const decision = decisions[index];
    if (!ip || !decision) return;
    if (decision.action === 'record') recordIps.add(ip);
    if (decision.action !== 'block') return;

    const alertId = safeAlertId(alert);
    const timestamp = Date.parse(alert.timestamp);
    if (!alertId || !Number.isFinite(timestamp)) return;

    const entry = blockByIp.get(ip) ?? { ip, alertIds: [], latestAt: 0 };
    if (!entry.alertIds.includes(alertId)) entry.alertIds.push(alertId);
    entry.latestAt = Math.max(entry.latestAt, timestamp);
    blockByIp.set(ip, entry);
  });

  const rules = [];
  const skipped = [];
  for (const entry of blockByIp.values()) {
    if (recordIps.has(entry.ip)) {
      skipped.push({ alertIds: entry.alertIds, reason: 'record_from_same_source' });
      continue;
    }
    rules.push({
      ruleId: RULE_ID,
      effect: 'deny',
      match: { srcip: entry.ip },
      expiresAt: new Date(entry.latestAt + BLOCK_TTL_MS).toISOString(),
      alertIds: entry.alertIds,
    });
  }
  return { rules, skipped };
}

// 판정기 확인 단계에서 쓰는 조회: 만료 전 거부 규칙에 걸리는 출발 주소인지 봅니다.
export function isSourceBlocked(srcip, atMs, rules) {
  if (typeof srcip !== 'string' || !DOC_IP.test(srcip) || !Number.isFinite(atMs)
      || !Array.isArray(rules)) return null;
  const hit = rules.find((rule) => (
    rule?.ruleId === RULE_ID
      && rule.match?.srcip === srcip
      && Number.isFinite(Date.parse(rule.expiresAt))
      && atMs < Date.parse(rule.expiresAt)
  ));
  return hit ? { blocked: true, ruleId: hit.ruleId, alertIds: hit.alertIds } : null;
}

function logLine(alert, decision) {
  return JSON.stringify({
    at: alert.timestamp,
    moduleKey: 'persistence',
    alertId: safeAlertId(alert),
    action: decision.action,
    confidence: decision.confidence,
    reason: decision.reason,
    srcip: sourceIp(alert),
  });
}

export async function respond() {
  const fixture = JSON.parse(await readFile(FIXTURE, 'utf8'));
  const alerts = Array.isArray(fixture.alerts) ? fixture.alerts : [];
  const decisions = await Promise.all(alerts.map((alert) => decide(alert)));
  const { rules, skipped } = buildDenyRules(alerts, decisions);
  await writeFile(DENY_RULES, `${JSON.stringify({
    schema: 'aleph.xdr.deny-rules.v1',
    moduleKey: 'persistence',
    rules,
    skipped,
  }, null, 2)}\n`, 'utf8');

  const lines = alerts
    .map((alert, index) => (
      decisions[index].action === 'record' ? null : logLine(alert, decisions[index])
    ))
    .filter(Boolean);
  await mkdir(dirname(ALERTS_LOG), { recursive: true });
  if (lines.length > 0) await appendFile(ALERTS_LOG, `${lines.join('\n')}\n`, 'utf8');

  // 시험 경보를 다시 흘려 거부 규칙에 걸리는지 확인합니다.
  const replay = {
    blocked: { block: 0, alert: 0, record: 0 },
    passed: { block: 0, alert: 0, record: 0 },
  };
  alerts.forEach((alert, index) => {
    const hit = isSourceBlocked(sourceIp(alert), Date.parse(alert.timestamp), rules);
    replay[hit ? 'blocked' : 'passed'][decisions[index].action] += 1;
  });
  return { rules, skipped, logged: lines.length, replay };
}

const isMain = process.argv[1]
  && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  const result = await respond();
  console.log(`거부 규칙 ${result.rules.length}개 · 제외 ${result.skipped.length}개 · alerts.log ${result.logged}줄 추가`);
  console.log(`다시 확인: 막힘 ${JSON.stringify(result.replay.blocked)} · 통과 ${JSON.stringify(result.replay.passed)}`);
  if (result.replay.blocked.record > 0) process.exitCode = 1;
}
