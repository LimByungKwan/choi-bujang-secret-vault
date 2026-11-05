// 보너스 xdr-06 제작 3 · 판단 모듈 (exfiltration)
// 바깥 파일·패키지를 불러오지 않고, 파일을 읽거나 쓰지 않으며, 네트워크를 쓰지 않습니다.
// 아래 PATTERNS 는 xdr/exfiltration/patterns.json 의 패턴을 그대로 옮겨 적은 상수입니다.
const PATTERNS = Object.freeze([
  Object.freeze({
    name: 'large_transfer_to_unfamiliar_destination',
    condition: 'rule.level 이 10 이상이고 data.dstip 이 있으며 data.bytes 가 대용량이고, 설명이 처음 보는 목적지나 주소("처음 보는 목적지", "처음 보는 주소")를 말한다.',
    evidence: 'T1041 의 탐지 지침은 드문 외부 목적지로의 통신을, T1048 의 탐지 지침은 평소보다 많은 전송량을 살피므로 처음 보는 목적지로의 대용량 전송은 두 기법의 뚜렷한 신호다.',
  }),
  Object.freeze({
    name: 'off_hours_archive_exfiltration',
    condition: 'rule.level 이 10 이상이고 data.dstip 이 있으며 data.bytes 가 대용량이고, 설명에 "수업 시간 밖" 또는 "업무 시간 밖" 과 압축 파일이 함께 있다. timestamp 로 계산하지 않는다.',
    evidence: 'T1048 의 탐지 지침은 업무 시간 밖의 파일 전송을 살피고 사례에 압축한 자료의 반출이 있으므로, 업무 시간 밖의 압축 파일 대용량 전송은 그 뚜렷한 형태다.',
  }),
  Object.freeze({
    name: 'repeated_large_transfer_same_destination',
    condition: 'rule.level 이 10 이상이고 data.dstip 이 있으며 data.bytes 가 대용량이고, data.count 가 5 이상이다.',
    evidence: 'T1048 의 탐지 지침은 평소보다 많은 전송량을 살피므로, 한 목적지로 대용량 전송을 되풀이하는 것은 그 전송량을 쌓는 형태다.',
  }),
  Object.freeze({
    name: 'bulk_file_transfer',
    condition: 'rule.level 이 10 이상이고 data.dstip 이 있으며 data.bytes 가 대용량이고, data.files 가 50 이상이다.',
    evidence: 'T1041 의 탐지 지침은 대량 전송 세션을 살피므로, 많은 파일이 한꺼번에 큰 용량으로 나가는 것은 그 뚜렷한 형태다.',
  }),
  Object.freeze({
    name: 'unusual_port_transfer',
    condition: 'rule.level 이 10 이상이고 data.dstip 이 있으며 data.bytes 가 대용량이고, 설명이 평소에 쓰지 않던 포트로 전송했다고 말한다.',
    evidence: 'T1048 은 기존 명령 통로와 다른 프로토콜로 자료를 빼내는 기법이므로, 평소에 쓰지 않던 포트로 나가는 대용량 전송은 다른 경로를 쓴 반출로 의심할 근거다.',
  }),
  Object.freeze({
    name: 'c2_channel_large_transfer',
    condition: 'rule.level 이 10 이상이고 data.dstip 이 있으며 data.bytes 가 대용량이고, 설명이 명령 통로로 전송했다고 말한다.',
    evidence: 'T1041 은 기존 명령 통로로 자료를 빼내는 기법이므로, 명령 통로로 나가는 대용량 전송은 그 직접적인 형태다.',
  }),
  Object.freeze({
    name: 'unverified_transfer_review',
    condition: 'rule.mitre 에 T1041 또는 T1048 이 있고 rule.level 이 5 이상이나 위 패턴이 성립하지 않는다. 전송 실패(bytes 0), 부정 문구, 작은 전송, 평소 목적지처럼 뚜렷한 신호가 없는 경우다. 차단하지 않고 알림으로만 남긴다.',
    evidence: 'T1041 과 T1048 은 자료가 실제로 빠져나가는 기법이므로, 실패했거나 아직 전송되지 않았거나 양이 적은 흔적은 두 기법으로 확정할 수 없는 검토 대상이다.',
  }),
]);

const PATTERN_NAMES = new Set(PATTERNS.map((p) => p.name));

const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;
const MIN_BLOCK_LEVEL = 10;
const MIN_REVIEW_LEVEL = 5;
const LARGE_BYTES = 50000000;
const MIN_REPEAT_COUNT = 5;
const MIN_BULK_FILES = 50;
const MAX_TEXT = 8192;

const EXFILTRATION_TECHNIQUES = ['T1041', 'T1048'];
const NEGATION_TEXT = /취소|실패|없습니다|아닙니다/u;
const UNFAMILIAR_DESTINATION_TEXT = /처음 보는 (?:목적지|주소)/u;
const OFF_HOURS_TEXT = /수업 시간 밖|업무 시간 밖/u;
const ARCHIVE_TEXT = /압축 파일/u;
const UNUSUAL_PORT_TEXT = /평소에 쓰지 않던 포트/u;
const C2_CHANNEL_TEXT = /명령 통로/u;
const DIGITS = /^\d{1,18}$/u;

function record(reason) {
  return { action: 'record', confidence: 0, reason };
}

function round2(value) {
  return Math.round(value * 100) / 100;
}

function clamp(value, low, high) {
  return Math.min(high, Math.max(low, value));
}

function isRecord(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function boundedText(value) {
  return typeof value === 'string' && value.length <= MAX_TEXT ? value : '';
}

// 경보의 숫자는 문자열입니다. 숫자로 읽을 수 없으면 null 로 두어 패턴에 맞지 않게 합니다.
function amount(value) {
  if (typeof value === 'number') return Number.isFinite(value) && value >= 0 ? value : null;
  return typeof value === 'string' && DIGITS.test(value) ? Number(value) : null;
}

function reasonOf(matched) {
  return matched.filter((name) => PATTERN_NAMES.has(name)).join(', ');
}

// 뚜렷한 패턴은 수준 10 이상 + 대용량 + 목적지 있음 + 부정 문구 없음일 때만 봅니다.
function clearPatterns(level, description, data) {
  const bytes = amount(data.bytes);
  const hasDestination = typeof data.dstip === 'string' && data.dstip.trim() !== '';
  if (level < MIN_BLOCK_LEVEL || bytes === null || bytes < LARGE_BYTES || !hasDestination
      || NEGATION_TEXT.test(description)) {
    return [];
  }

  const count = amount(data.count);
  const files = amount(data.files);
  const matched = [];
  if (UNFAMILIAR_DESTINATION_TEXT.test(description)) {
    matched.push('large_transfer_to_unfamiliar_destination');
  }
  if (OFF_HOURS_TEXT.test(description) && ARCHIVE_TEXT.test(description)) {
    matched.push('off_hours_archive_exfiltration');
  }
  if (count !== null && count >= MIN_REPEAT_COUNT) {
    matched.push('repeated_large_transfer_same_destination');
  }
  if (files !== null && files >= MIN_BULK_FILES) matched.push('bulk_file_transfer');
  if (UNUSUAL_PORT_TEXT.test(description)) matched.push('unusual_port_transfer');
  if (C2_CHANNEL_TEXT.test(description)) matched.push('c2_channel_large_transfer');
  return matched;
}

function evaluate(alert) {
  if (!isRecord(alert) || !isRecord(alert.rule) || !isRecord(alert.data)
      || !Number.isFinite(alert.rule.level)) {
    return record('invalid_input');
  }

  const level = alert.rule.level;
  const description = boundedText(alert.rule.description);
  const mitre = Array.isArray(alert.rule.mitre) ? alert.rule.mitre : [];
  const matched = clearPatterns(level, description, alert.data);

  if (matched.length > 0) {
    // 맞는 패턴이 더 있거나 수준이 높으면 확신도를 높입니다.
    const confidence = round2(clamp(
      BLOCK_AT + (level - MIN_BLOCK_LEVEL) * 0.01 + (matched.length - 1) * 0.03,
      BLOCK_AT,
      0.99,
    ));
    return { action: 'block', confidence, reason: reasonOf(matched) };
  }

  const hasTechnique = EXFILTRATION_TECHNIQUES.some((id) => mitre.includes(id));
  if (hasTechnique && level >= MIN_REVIEW_LEVEL && level < MIN_BLOCK_LEVEL) {
    const confidence = round2(clamp(
      ALERT_AT + (level - MIN_REVIEW_LEVEL) * 0.05,
      ALERT_AT,
      0.7,
    ));
    return { action: 'alert', confidence, reason: reasonOf(['unverified_transfer_review']) };
  }

  return record('no_pattern_match');
}

export function decide(alert) {
  try {
    return evaluate(alert);
  } catch {
    return record('invalid_input');
  }
}
