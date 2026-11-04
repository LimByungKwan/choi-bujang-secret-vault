// Pure, import-free decision module for the web-injection fixture.
const PATTERNS = Object.freeze([
  Object.freeze({
    name: 'sql_injection_syntax',
    condition: '요청 URL에 doc-sql-chain, doc-sql-or 또는 doc-sql-select-chain 표식이 있다. sql, select 또는 or 단어 하나만으로는 해당하지 않는다.',
    evidence: 'MITRE ATT&CK T1190은 공개 애플리케이션의 입력 처리 취약점을 악용하는 공격을 다루며, 요청 인자의 결합 SQL 구문은 해당 악용 시도의 표식이다.',
  }),
  Object.freeze({
    name: 'script_tag',
    condition: '요청 URL에 doc-script-marker 표식이 있다. script 수업 단어 하나만으로는 해당하지 않는다.',
    evidence: 'MITRE ATT&CK T1190은 공개 앱 입력을 통한 악용을 다루며, 요청 인자의 script 태그 구조는 입력 처리 악용을 식별하는 표식이다.',
  }),
  Object.freeze({
    name: 'repeated_path_traversal',
    condition: '요청 URL에 doc-up-repeat 표식이 있다. 단일 up 단어만으로는 해당하지 않는다.',
    evidence: 'MITRE ATT&CK T1190은 공개 앱의 경로 처리 악용을 포함하며, 반복된 상위 경로 이탈 표기는 파일 경로 경계 우회 시도의 표식이다.',
  }),
  Object.freeze({
    name: 'command_separator',
    condition: '요청 URL에 doc-cmd-separator 표식이 있다. 단독 구분 문자는 반복·수준 조건 없이 공격으로 보지 않는다.',
    evidence: 'MITRE ATT&CK T1190은 공개 앱 입력이 명령 처리로 이어지는 악용을 다루며, 명령 연결 문맥의 구분자 구조는 해당 입력 표식이다.',
  }),
  Object.freeze({
    name: 'mixed_script_sql',
    condition: '요청 URL에 스크립트와 SQL이 혼합된 doc-mixed-marker 표식이 있다.',
    evidence: 'MITRE ATT&CK T1190은 공개 애플리케이션 입력을 악용하는 공격을 다루며, 혼합된 스크립트·SQL 표식은 입력 처리 악용 시도의 근거다.',
  }),
  Object.freeze({
    name: 'single_attempt',
    condition: '같은 주소에서 반복되지 않은 data.count 1건이고 rule.level이 5~8인 단발 시도다. 수업 단어를 포함해도 차단하지 않는다.',
    evidence: 'MITRE ATT&CK T1190은 공개 애플리케이션 입력을 통한 악용을 다루며, 반복이 확인되지 않은 입력은 추가 검토 대상으로 알리고 차단하지 않는다.',
  }),
]);

const BLOCK_AT = 0.85;
const MIN_BLOCK_COUNT = 8;
const MIN_BLOCK_LEVEL = 10;

const SIGNATURES = Object.freeze([
  ['sql_injection_syntax', /\bdoc-sql-(?:chain|or|select-chain)\b/iu],
  ['script_tag', /\bdoc-script-marker\b/iu],
  ['repeated_path_traversal', /\bdoc-up-repeat\b/iu],
  ['command_separator', /\bdoc-cmd-separator\b/iu],
  ['mixed_script_sql', /\bdoc-mixed-marker\b/iu],
]);

function record(reason = 'invalid_input') {
  return { action: 'record', confidence: 0, reason };
}

function decodeRequest(value) {
  return decodeURIComponent(value.replace(/\+/gu, ' '));
}

function evaluate(alert) {
  if (!alert || typeof alert !== 'object' || Array.isArray(alert)) return record();
  const data = alert.data;
  const rule = alert.rule;
  if (!data || typeof data !== 'object' || Array.isArray(data)
      || !rule || typeof rule !== 'object' || Array.isArray(rule)) {
    return record();
  }

  const url = data.url;
  const srcip = data.srcip;
  const level = rule.level;
  if (typeof url !== 'string' || url.length > 8192
      || typeof srcip !== 'string' || srcip.trim().length === 0 || srcip.length > 64
      || !Number.isFinite(level)) {
    return record();
  }

  const docMarker = /doc-[a-z0-9_-]+/iu.test(url);
  const countValue = data.count;
  const count = countValue === undefined ? null : Number(countValue);
  if (count !== null && (!Number.isFinite(count) || count < 0)) return record();

  let requestText;
  try {
    requestText = decodeRequest(url);
  } catch {
    requestText = url;
  }
  const matched = SIGNATURES.find(([name, signature]) => (
    PATTERNS.some(pattern => pattern.name === name) && signature.test(requestText)
  ));

  if (count === 1 && level >= 5 && level <= 8) {
    const confidence = Math.round((0.55 + (level - 5) * 0.05) * 100) / 100;
    return { action: 'alert', confidence, reason: 'single_attempt' };
  }

  if (level <= 4 && !docMarker) return record('normal_low_level');
  if (!docMarker || count === null || !matched) {
    return record(!docMarker ? 'missing_doc_marker' : 'no_injection_pattern');
  }
  if (count < MIN_BLOCK_COUNT || level < MIN_BLOCK_LEVEL) {
    return record('below_block_threshold');
  }

  const confidence = Math.min(0.99, 0.85 + Math.min(0.1, (count - MIN_BLOCK_COUNT) / 100)
    + Math.min(0.04, (level - MIN_BLOCK_LEVEL) / 100));
  const roundedConfidence = Math.round(confidence * 100) / 100;
  const action = roundedConfidence >= BLOCK_AT ? 'block' : 'alert';
  return { action, confidence: roundedConfidence, reason: matched[0] };
}

export function decide(alert) {
  try {
    return evaluate(alert);
  } catch {
    return record();
  }
}
