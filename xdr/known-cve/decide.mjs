// 보너스 xdr-03 제작 3 · 판단 모듈 (known-cve)
// 바깥 파일·패키지를 불러오지 않고, 파일을 읽거나 쓰지 않으며, 네트워크를 쓰지 않습니다.
// 아래 PATTERNS 는 xdr/known-cve/patterns.json 의 패턴을 그대로 옮겨 적은 상수입니다.
const PATTERNS = Object.freeze([
  Object.freeze({
    name: 'jndi_lookup_in_header',
    condition: '요청 머리글(data.useragent)에 `${jndi:` 로 시작하고 `://` 원격 주소가 이어지는 완전한 원격 조회 구문이 있다.',
    evidence: 'CVE-2021-44228 은 Log4j 가 기록한 머리글 속 `${jndi:…}` 조회를 해석해 원격 코드를 불러오는 취약점이며, T1190 은 이런 공개 앱 취약점 악용을 다룬다.',
  }),
  Object.freeze({
    name: 'jndi_lookup_in_argument',
    condition: '요청 인자(data.url 의 `?` 뒤 값)에 `${jndi:` 로 시작하고 `://` 원격 주소가 이어지는 완전한 원격 조회 구문이 있다.',
    evidence: 'CVE-2021-44228 은 기록되는 모든 입력값의 `${jndi:…}` 조회로 악용되므로 주소 인자 속 조회 구문도 같은 악용 시도이며, T1190 공개 앱 악용에 해당한다.',
  }),
  Object.freeze({
    name: 'jndi_lookup_multi_location',
    condition: '같은 경보의 요청 머리글과 요청 인자 양쪽에 완전한 원격 조회 구문이 함께 있다.',
    evidence: 'CVE-2021-44228 악용 시도는 어느 입력이 기록될지 모르기 때문에 여러 입력 위치에 같은 조회 구문을 넣으며, T1190 공개 앱 악용 시도의 뚜렷한 형태다.',
  }),
  Object.freeze({
    name: 'repeated_jndi_lookup',
    condition: '완전한 원격 조회 구문이 있고 같은 주소의 반복 횟수(data.count)가 2 이상이다.',
    evidence: 'CVE-2021-44228 공개 직후 같은 출발지에서 조회 구문을 반복해 보내는 대량 악용이 관찰됐으며, T1190 은 공개 앱 취약점을 노린 반복 악용 시도를 포함한다.',
  }),
  Object.freeze({
    name: 'scanner_probe_with_lookup',
    condition: '알려진 취약점 점검 도구의 흔적(점검용 probe 인자 등)과 완전한 원격 조회 구문이 같은 요청에 함께 있다. 점검 도구와 비슷한 이름만 있고 조회 구문이 없으면 해당하지 않는다.',
    evidence: 'CVE-2021-44228 은 공개 직후 점검 도구로 영향받는 서버를 자동으로 찾는 데 쓰였으며, 조회 구문을 실은 점검 요청은 T1190 공개 앱 악용 시도다.',
  }),
  Object.freeze({
    name: 'cve_reference_without_lookup',
    condition: 'CVE-2021-44228 이름, jndi 단어, 라이브러리 이름, 중괄호, 잘린 조회 조각, 점검 도구와 비슷한 이름처럼 관련 흔적은 있으나 완전한 원격 조회 구문은 없고, rule.level 이 5~8 이다. 차단하지 않고 알림으로만 남긴다.',
    evidence: 'CVE-2021-44228 악용은 완전한 `${jndi:…://…}` 조회가 기록될 때만 성립하므로 이름·조각만 있는 요청은 T1190 악용으로 확정할 수 없는 검토 대상이다.',
  }),
]);

const PATTERN_NAMES = new Set(PATTERNS.map((p) => p.name));

const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;
const MIN_BLOCK_LEVEL = 10;
const MAX_TEXT = 8192;

// 완전한 원격 조회 구문: ${jndi:<프로토콜>://<주소>…}
const FULL_LOOKUP = /\$\{\s*jndi\s*:\s*[a-z][a-z0-9+.-]*\s*:\/\/[^}\s]+\}/iu;
// 점검 도구가 흔히 쓰는 점검용 인자 이름
const PROBE_PARAM = /(?:^|[?&;])(?:probe|scan|scanner|check|test)=/iu;
// 조회 구문은 없지만 이 취약점과 관련된 흔적
const RELATED_TRACE = /cve-?2021-?44228|jndi|log4j|log-?library|lookup|\$\{|[{}]|class-?(?:check|browser)|cve-?list/iu;

function record(reason) {
  return { action: 'record', confidence: 0, reason };
}

function round2(value) {
  return Math.round(value * 100) / 100;
}

function clamp(value, low, high) {
  return Math.min(high, Math.max(low, value));
}

// 인코딩(%24%7B…)과 흔한 감추기(${lower:j}, ${::-j})를 풀어 비교용 글자로 만듭니다.
function normalize(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_TEXT) return '';
  let text = value;
  for (let i = 0; i < 2; i += 1) {
    try {
      const decoded = decodeURIComponent(text.replace(/\+/gu, ' '));
      if (decoded === text) break;
      text = decoded;
    } catch {
      break;
    }
  }
  for (let i = 0; i < 5; i += 1) {
    const next = text
      .replace(/\$\{\s*(?:lower|upper)\s*:\s*([^{}$]*)\}/giu, '$1')
      .replace(/\$\{[^{}$:]*:-([^{}$]*)\}/gu, '$1');
    if (next === text) break;
    text = next;
  }
  return text;
}

function queryPart(url) {
  const at = url.indexOf('?');
  return at === -1 ? '' : url.slice(at + 1);
}

function evaluate(alert) {
  if (!alert || typeof alert !== 'object' || Array.isArray(alert)) return record('invalid_input');
  const data = alert.data;
  const rule = alert.rule;
  if (!data || typeof data !== 'object' || Array.isArray(data)
      || !rule || typeof rule !== 'object' || Array.isArray(rule)
      || !Number.isFinite(rule.level)) {
    return record('invalid_input');
  }

  const level = rule.level;
  const header = normalize(data.useragent);
  const url = normalize(data.url);
  const args = queryPart(url);

  let count = null;
  if (data.count !== undefined && data.count !== null && data.count !== '') {
    const parsed = Number(data.count);
    if (!Number.isFinite(parsed) || parsed < 0) return record('invalid_input');
    count = parsed;
  }

  const inHeader = FULL_LOOKUP.test(header);
  const inArgument = FULL_LOOKUP.test(args);

  if (inHeader || inArgument) {
    const matched = [];
    if (inHeader && inArgument) matched.push('jndi_lookup_multi_location');
    else if (inHeader) matched.push('jndi_lookup_in_header');
    else matched.push('jndi_lookup_in_argument');

    const scanner = inArgument && PROBE_PARAM.test(args);
    if (scanner) matched.push('scanner_probe_with_lookup');
    const repeated = count !== null && count >= 2;
    if (repeated) matched.push('repeated_jndi_lookup');

    // 완전한 구문 + 경보 수준 10 이상이면 뚜렷한 공격으로 봅니다.
    let confidence = level >= MIN_BLOCK_LEVEL
      ? 0.85 + (level - MIN_BLOCK_LEVEL) * 0.01
      : 0.6 + clamp(level, 0, 9) * 0.02;
    if (inHeader && inArgument) confidence += 0.05;
    if (repeated) confidence += 0.04;
    if (scanner) confidence += 0.03;
    confidence = round2(clamp(confidence, 0, 0.99));

    const action = confidence >= BLOCK_AT ? 'block' : 'alert';
    const reason = matched.filter((name) => PATTERN_NAMES.has(name)).join(', ');
    return { action, confidence, reason };
  }

  // 완전한 조회 구문은 없지만 이 취약점과 관련된 흔적이 있는 애매한 시도
  const mitre = Array.isArray(rule.mitre) ? rule.mitre : [];
  const t1190 = mitre.includes('T1190');
  const trace = RELATED_TRACE.test(header) || RELATED_TRACE.test(url);
  if (level >= 5 && (t1190 || trace)) {
    let confidence = 0.5 + (clamp(level, 5, 8) - 5) * 0.05;
    if (trace) confidence += 0.05;
    if (count !== null && count >= 2) confidence += 0.03;
    confidence = round2(clamp(confidence, ALERT_AT, 0.8));
    return { action: 'alert', confidence, reason: 'cve_reference_without_lookup' };
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
