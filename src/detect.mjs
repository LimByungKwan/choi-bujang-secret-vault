// 9단계에서 학생이 채우는 탐지 함수입니다. 이 기본값은 어떤 접속도 회수하지 않습니다.
// 반 엔진이 검증한 사건만 전달해야 하며, 브라우저가 보낸 사용자 번호는 받지 않습니다.
export function detect(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');
  const normalizedEvents = events.map((event) => ({
    at: event.at,
    method: event.method,
    sub: event.identity.sub,
  }));

  const readsBySubject = new Map();
  for (const event of normalizedEvents) {
    if (event.method !== 'GET') continue;
    const reads = readsBySubject.get(event.sub) ?? [];
    reads.push(event);
    readsBySubject.set(event.sub, reads);
  }

  let burstSubject;
  for (const reads of readsBySubject.values()) {
    reads.sort((left, right) => Date.parse(left.at) - Date.parse(right.at));
    let windowStart = 0;
    for (let windowEnd = 0; windowEnd < reads.length; windowEnd += 1) {
      while (
        Date.parse(reads[windowEnd].at) - Date.parse(reads[windowStart].at) >
        10 * 60 * 1000
      ) {
        windowStart += 1;
      }
      if (windowEnd - windowStart + 1 > 120) {
        burstSubject = reads[windowEnd].sub;
        break;
      }
    }
    if (burstSubject !== undefined) break;
  }

  if (burstSubject !== undefined) {
    return {
      action: 'propose_revocation',
      reasonCode: 'burst_read',
      subject: burstSubject,
    };
  }
  return { action: 'observe' };
}
