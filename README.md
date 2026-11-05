# BYTE BACK 방어전 R5 12단계 자료실

이 저장소는 Supabase Auth 인증과 메모 CRUD를 Vercel 서버 함수 뒤에서 처리하고, 6단계 기기 등록 및 7단계 가상 위험 기반 접근 정책을 구현한 R5 프로젝트입니다. 브라우저 정적 파일에는 Supabase SDK와 공개 키가 없으며, 실제 학생 자료, 토큰, 비밀키를 코드나 브라우저 파일에 넣지 마세요.

## 학생이 하는 일: 세 걸음

1. GitHub 계정을 만듭니다.
2. 방어전 카드의 **Deploy** 버튼을 누릅니다. Vercel에 GitHub로 로그인하고 저장소를 선택해 Deploy를 누릅니다.
3. 배포가 끝나면 화면에 나온 `https://…vercel.app` 주소를 현재 단계 카드에 제출합니다. 저장소 주소나 설정 파일은 적지 않습니다.

배포가 끝나면 `/` 화면에서 Supabase 학습 계정으로 로그인할 수 있습니다. 브라우저는 `/api/auth/login`, `/api/auth/session`, `/api/auth/logout`을 호출하며, 서버가 Supabase Auth와 통신합니다. 액세스·갱신 토큰은 서버가 `HttpOnly`, `Secure`, `SameSite=Strict` 쿠키로 관리하고 응답 JSON에 반환하지 않습니다. 상태 변경 요청은 Origin 및 CSRF 검사를 거칩니다. 메모 자료는 `GET`·`POST /api/notes`와 `GET`·`PUT`·`DELETE /api/notes/{id}` 서버 함수만 사용합니다. 서버는 `src/verify-login.mjs`로 로그인 사용자를 확인하고, 목록·단건 조회·수정·삭제는 검증된 사용자의 메모에만 적용합니다. 메모 생성 시 소유자는 서버가 검증한 사용자 ID로 설정하며 요청 본문의 `owner_id`는 사용하지 않습니다. 기존 헤더 기반 인증 호환성도 유지합니다. `public/data.json`은 빌드에서 제거되며 더 이상 생성되지 않습니다.

단일 메모 API는 ID와 함께 `owner_id`를 데이터베이스 쿼리 조건으로 확인해 타인 메모와 존재하지 않는 메모에 동일하게 404를 반환합니다. 메모 API는 서버 전용 `SUPABASE_SECRET_KEY`를 사용하고, 이 키를 브라우저 파일이나 응답에 넣지 않습니다.

## 가상 메모 잔존 확인

다음 문장 네 개를 각각 정확한 문구로 검색하세요.

- `실습용 가상 과제 기록`
- `실습용 가상 포트폴리오 기록`
- `실습용 가상 리추얼 기록`
- `실습용 가상 행정 기록`

GitHub에서는 저장소의 **Code** 검색에서 기본 브랜치의 최신 파일을 대상으로 위 문장들을 하나씩 검색하세요. 현재 구성이라면 검색 결과는 이 확인 절차가 있는 README와 `supabase/migrations/`의 SQL에만 있어야 합니다. `data.json`은 빈 목록이고 `public/data.json`은 없어야 합니다.

Vercel에서는 **Deployments**에서 현재 Production 배포를 열고, 배포 주소의 `/`와 `/aleph.json` 등 정적 파일 내용에서 같은 문장을 검색하세요. 여기서는 문장이 나오지 않아야 하며 `/data.json`은 404여야 합니다. 기존 가상 메모 네 건과 B 계정 시험 메모 한 건은 Supabase 테이블에 보존되어 있습니다. 제작 1의 검증 결과 A 소유 메모 네 건, B 소유 메모 한 건입니다. 각 계정은 자기 메모만 조회할 수 있습니다. 로그인하지 않은 채 `/api/notes` 또는 `/api/notes/{id}`의 자료 요청을 보내면 JSON 인증 오류가 반환되어야 합니다.

## 5단계 검증 기록

Supabase에서 `public.learning_notes`에 대한 `PUBLIC`·`anon`·`authenticated` 직접 CRUD 권한을 회수하고 `service_role` CRUD 권한은 유지했습니다. 본인 소유 RLS 정책 네 개와 기존 A/B 계정 및 메모 다섯 건은 보존했습니다. 계정별 시험에서 A 메모 CRUD와 B 메모 조회가 정상 동작했고, 비로그인 서버 API는 HTTP 401, A/B 계정의 원본 Supabase REST API 직접 GET은 HTTP 403을 반환했습니다. 첫 화면 응답의 `X-Content-Type-Options: nosniff`도 실제 배포에서 확인했습니다. 이 결과는 배포 점검 기록이며, 로컬 테스트나 빌드만으로 대체할 수 없습니다.

인증 서버화에서는 브라우저 로그인·새로고침 후 세션 유지와 로그아웃, A 계정의 메모 추가·수정·삭제 및 B 계정의 기존 메모 조회를 Production에서 확인했습니다. 배포된 `/`와 `/app.js`에서 공개 키, Supabase SDK, JWT 패턴이 검출되지 않았습니다. `npm.cmd test`는 17개 테스트가 통과했고 `npm.cmd run build -- --local`도 성공했습니다. 이는 배포·계정 검증과 로컬 자동 테스트를 구분해 기록한 결과입니다.

이 절차는 GitHub 최신 파일과 현재 배포만 확인합니다. 옛 공개 커밋이나 이전 배포가 남아 있는 동안에는 과거 노출이 해소됐다고 쓰지 마세요. 과거 커밋과 이전 배포 주소도 별도로 확인하고, 남아 있다면 과거 노출은 계속된 것으로 취급해야 합니다.

## 6단계 · 등록 기기 기반 접근 정책

### 해결 과제

미등록 기기의 자료실 접근을 거부하는 정책을 구현했습니다.

### 구현 내용

- `src/decider.mjs`에 `device_registered` 규칙을 구현했습니다.
- 계약의 `deviceRegistered` 값이 정확히 `true`일 때만 `allow`를 반환합니다.
- `false` 또는 값이 누락된 경우 `deny`를 반환하고, 거부 사유는 `device_not_registered`입니다.
- 요청·응답 계약을 준수하며, `RULE_IDS`에는 구현한 `device_registered` 규칙을 등록합니다.

### 테스트 및 검증

- `npm.cmd run decider:test`: 가상 요청 2개 통과
- `deviceRegistered` 누락 입력: `deny` 확인
- `npm.cmd test`: 기존 17개 테스트 통과, 실패 0개

위 판정기 연습은 로컬 가상 요청 검증이며, 실제 운영 심판의 판정이나 실제 접속 통제를 증명하지 않습니다.

### 설계 근거

- Fail-Closed 원칙에 따라 등록 여부가 확인되지 않으면 거부합니다.
- 운영 엔진이 확인해 전달한 기기 등록 정보를 사용합니다.
- 클라이언트가 임의로 전달한 기기 상태를 신뢰하지 않습니다.

### 구현 범위와 한계

- 로컬 판정기 구현과 가상 요청 검증 범위입니다.
- 실제 mTLS 연결과 인증서 발급은 구현하지 않았습니다.
- 이 정책이 기존 Vercel 메모 API에 직접 연결된 것으로 간주하지 않습니다.
- 실제 심판 점수는 아직 확인하지 않았습니다.

### 재현 방법

Windows에서는 다음 명령으로 의존성을 설치하고 검증할 수 있습니다.

```shell
npm.cmd install
npm.cmd run decider:test
npm.cmd test
```

판정기 연습 결과에서 등록 기기의 정상 요청은 허용되고 미등록 기기의 가상 요청은 거부되는지 비교하세요.

### 포트폴리오 의미

- 정책 결정기(PDP) 구현
- 기기 기반 접근 제어
- 안전한 기본 거부 정책
- 자동화된 보안 검증

6단계 심판 최종 점수는 사용자가 확인한 **100/100점**입니다. 이는 심판 결과 기록이며, `device_registered` 판정 규칙 구현 및 로컬 검증 사실과 구분합니다. 점수는 이번 저장소 작업에서 독립적으로 재검증하지 않았습니다.

## 7단계 · 평소와 다른 접속은 다시 확인합니다

### 해결 과제와 구현

등록된 기기에서 발생한 가상 복합 이상 접속에 추가 확인을 요구하는 정책을 기존 판정기에 추가했습니다.

- `device_registered` 규칙을 유지해 `deviceRegistered === true`인 등록 기기는 기본적으로 허용하고, 미등록 또는 등록 여부가 없는 기기는 `device_not_registered` 사유로 거부합니다.
- `step_up_required` 규칙을 추가했습니다. 로컬 가상 사건 조건이 함께 맞고 유효한 재확인 정보가 없으면 `step_up`을 반환합니다.
- 등록 기기의 정상 가상 요청은 `allow`, 미등록 기기는 `deny`, 가상 복합 이상 요청은 `step_up`으로 판정합니다.
- 가상 복합 이상 요청에 계약상 범위의 `stepUp.verified`와 `stepUp.authAgeSeconds`가 있으면 가상 판정은 `allow`가 됩니다. 이는 실제 재로그인이나 세션 재검증을 뜻하지 않습니다.

### 입력 출처와 신뢰 경계

판정기는 `docs/DECIDER_REQUEST.md`에 정의된 `deviceRegistered`, `signals`, `recentEvents`, `stepUp`만 사용합니다. 엔진이 전달하는 입력을 검사하며, 계약에 없는 클라이언트 필드를 추가하거나 읽지 않습니다.

- `signals.source: "judge_fixture"`는 로컬 가상 사건 분류에만 사용하며 실제 위치 증거로 취급하지 않습니다.
- `source: "none"` 및 `region`·`network`의 `unknown`은 위치·네트워크가 확인되지 않은 상태이며 정상 접속의 증거로 사용하지 않습니다. 그 밖에 확인되지 않은 출처도 신뢰 가능한 위치 증거로 승격하지 않습니다.
- 위험 검사는 기존 입력 구조 검사 결과를 사용합니다. 잘못되었거나 누락된 신호·사건은 정상값으로 보정하지 않으며 위험 근거로 사용하지 않습니다. 다만 잘못된 입력을 차단할 공식 이유 코드와 처리 규칙은 확인되지 않았습니다.
- 로컬 복합 위험 조건은 `judge_fixture`, `network: "unusual"`, `hour: 3`, 그리고 `risk_signal` 사건의 `count: 20`, `ageSeconds: 60`이 모두 맞는 경우입니다. 지역 값 하나만으로 `step_up`을 요구하지 않습니다.

이 고정값은 기존 가상 fixture를 재현하기 위한 사례일 뿐, 운영에서 검증된 위험 임계값이나 범용 위험 점수가 아닙니다.

### 테스트 및 검증 기록

다음은 이번 단계에서 실제 실행한 로컬 확인이며, 운영 연결이나 심판 판정이 아닙니다.

- `npm.cmd run fixture:7`: 정상 사건 `allow`, 복합 이상 사건 `step_up`
- `npm.cmd run decider:test`: 등록 기기 허용, 미등록 기기 거부, 복합 이상 `step_up`, 재확인 정보가 있는 가상 요청 허용 등 4개 사례 통과
- `npm.cmd test`: 기존 17개 테스트 통과, 실패 0개
- `node --check src/decider.mjs`: 통과
- 추가 가상 경계 사례 13개: 미등록·누락 기기, 지역 단독, `source: "none"` 및 미확인 출처, 잘못되거나 누락된 위험 입력, 재확인 상태 등을 확인
- `npm.cmd run decider`: `package.json`에 해당 스크립트가 없어 실행 실패. 등록된 판정기 연습 명령은 `npm.cmd run decider:test`입니다.

### 구현 범위와 한계

- 판정기와 fixture는 로컬 가상 요청을 다루며 실제 Vercel 메모 API와 연결되지 않습니다.
- 실제 재로그인, 동일 사용자·세션의 재인증 시각 검증, `step_up` 이전 메모 접근 차단은 구현되지 않았습니다.
- `step_up.verified`와 `authAgeSeconds`를 검사하는 로직은 가상 요청 입력 검사이며, 재로그인 완료 증명이 아닙니다.
- 운영 `allowedReasonCodes` 등록부에서 `approved`, `device_not_registered`, `step_up_required`가 허용되는지는 확인되지 않았습니다.
- 7단계 심판 최종 점수는 사용자가 확인한 **100/100점**입니다. 로컬 통과 결과로 심판 점수를 추정한 것이 아니며, 이번 저장소 작업에서 독립적으로 재검증하지 않았습니다.

### 포트폴리오 의미

- 정책 결정기(PDP)에서 기기 등록 정책과 위험 기반 추가 확인 분기를 함께 설계하는 역량
- 입력 계약 검증, 출처별 신뢰 경계, fail-closed 기기 거부를 고려하는 보안 설계 역량
- 가상 fixture와 회귀 테스트로 정책 동작을 검증하고 운영 미연동·미확인 계약을 명확히 문서화하는 AI Agent 개발 역량

## 8단계 · 자료마다 갈 수 있는 구역을 나눕니다

### 해결 과제와 구현

서로 다른 자료의 무단 조회·수정과 수평적 권한 상승(IDOR/BOLA)을 방지하는 설계를 추가했습니다.

- **제작 1 — 자원 식별:** 기존 메모 UUID를 보존하면서 `note`, `class-announcement`, `instructor-material` 유형을 구분하는 `resourceId` 체계를 마련했습니다. 실제 공지·강사 자료 데이터나 권한을 만들지는 않았습니다.
- **제작 2 — 자원 접근 판정:** `service`, HTTP `method`, `path`, `route` 조합을 분류해 개인 메모 단건 GET과 로컬 공지 GET을 허용 후보로 분류하고, 메모 목록·쓰기, 강사 자료, 미지원·위장 경로는 거부합니다. 판정 순서는 **기기 등록 → 자원 접근 → 복합 위험 판정**입니다.
- **제작 3 — 서버 API 권한 검증:** 기존 메모 API의 소유권 조건을 확인했습니다. 단건 조회·수정·삭제는 저장된 `owner_id`와 검증된 `identity.userId`를 함께 DB 조건으로 사용하고, 생성 소유자는 서버가 지정합니다. 지원하지 않는 중첩·관리 경로는 목록 요청으로 처리하지 않고 DB 접근 전에 거부합니다.
- 판정기와 실제 서버 API의 권한 검사를 분리하는 **B안(이중 검증)**을 선택했습니다. 브라우저의 기존 로그인 사용자별 메모 목록 기능은 유지했습니다.
- A/B 계정의 기존 메모 다섯 건, Supabase Auth/JWT 검증, HttpOnly·Secure·SameSite 쿠키, Origin·CSRF 검사, owner_id 검사 및 RLS 정책은 변경하지 않았습니다. 소유권 공격 테스트는 격리된 모의 저장소를 사용했으며 운영 DB를 수정하지 않았습니다.
- 테스트 도중 모의 요청에서 URL이 누락된 경우 새 경로 분류가 기존 목록 요청을 거부하는 회귀를 발견했습니다. 기본 경로를 기존 `/api/notes`로 맞춘 뒤 회귀 테스트를 다시 실행해 통과를 확인했습니다.

### 로컬 테스트 기록

아래는 로컬 테스트 결과이며 실제 심판 판정이나 운영 접속 결과가 아닙니다.

- `npm.cmd test`: 19개 통과
- `node --test test/decider-resource-access.test.mjs`: 6개 통과
- `node --test test/resource-access.test.mjs`: 8개 통과
- `npm.cmd run decider:test`: 가상 요청 4개 통과
- `npm.cmd run fixture:7`: 정상 요청 `allow`, 복합 이상 요청 `step_up`

테스트 범위는 일부 겹칩니다. 전체 `npm.cmd test`에는 메모 API·인증·설정 회귀가 포함되며, 자원 분류기 8개와 판정기 통합 6개는 별도 실행한 집중 테스트입니다. `decider:test`와 `fixture:7`은 모두 7단계 가상 판정 동작을 확인하므로 심판 또는 운영 연동의 독립 증거가 아닙니다.

### 구현 범위와 한계

- `resource_access_denied`는 로컬 후보 코드입니다. 운영 `allowedReasonCodes` 등록 여부는 확인되지 않았습니다.
- 공지·강사 자료의 `service`·`path`·`route`는 로컬 제안 규약이며 운영 경로 계약이 아닙니다.
- 실제 강사 역할 검증과 공지 API는 구현되지 않았습니다.
- 현재 판정기는 Vercel 메모 API와 직접 연결되지 않습니다.
- `aleph.config.json`의 `allowedRoutes`는 제출 설정에 기록되는 판정기 허용 경로입니다. 실제 Vercel API 요청을 직접 차단하지 않습니다.
- 8단계 심판 최종 점수는 사용자가 실제 확인한 **100/100점**입니다. 로컬 테스트 결과와 구분한 심판 결과 기록입니다.

### 포트폴리오 기록

- **내가 결정한 것:** 판정기 분류만으로 실제 API 권한이 보장된다고 간주하지 않고 B안 이중 검증을 선택했습니다. 기존 메모 목록 기능은 유지했습니다.
- **나의 아이디어:** URL 인코딩, 인코딩된 구분자, 추가 경로, 서비스·메서드·route 불일치 테스트를 보강해 경로 위장과 우회 가능성을 확인했습니다.
- **공부한 것:** 인증과 인가의 차이, 경로 정규화, 기본 거부 원칙, 정책 결정기와 실제 서버 소유권 검증의 역할 차이를 익혔습니다.
- **AI Agent 연결:** 사용자·자원·행동별 도구 권한 검사에도 같은 이중 검증 원칙을 응용할 수 있습니다. 실제 AI Agent 도구 연동은 구현하지 않았습니다.

**면접 예상 질문:** “판정기에서 허용한 요청이면 실제 API에서도 안전한가요?”
**답변:** “아닙니다. 판정기는 로컬 요청 계약의 경로 후보를 분류하고 실제 메모 API에 연결되어 있지 않습니다. 실제 API는 로그인 검증에서 얻은 사용자 ID를 저장된 `owner_id`와 매번 비교합니다. 두 계층을 따로 검사하고, 운영 경로·거부 사유 계약이 확인되지 않은 부분은 미완료로 구분했습니다.”

## 9단계 · 이상 조회를 탐지하고 회수 제안을 만듭니다

### 해결 과제와 입력 계약

같은 사용자에게 짧은 시간 동안 조회가 집중되는 이상 조회를 찾아내되, 가상 사건 계약의 범위를 지키는 탐지 함수를 구현했습니다. 사건에서는 `at`, `method`, `identity.sub`만 읽어 내부 입력으로 정리합니다. GET 사건만 탐지하고, IP·네트워크·기기·지역 등 계약에 없는 정보는 사용하지 않습니다.

### 구현과 설계 결정

- `Map`으로 `sub`별 GET 사건을 분리하고, 복사한 내부 사건을 `at` 기준으로 정렬해 원본 배열을 변경하지 않습니다.
- 시간순 사건을 슬라이딩 윈도우로 검사합니다. 같은 `sub`의 GET 사건이 10분 구간에서 120건을 초과하면 해당 `sub`를 `subject`로 한 `propose_revocation` 제안을 반환하며, 120건 이하는 `observe`입니다.
- **B안(회수 제안만 반환)**을 선택했습니다. 현재 함수는 판정 결과만 돌려주며 실제 계정·기기·세션 권한을 회수하지 않습니다.
- 비교한 **A안(자동 회수)**은 대응이 빠르다는 장점이 있지만, 오탐만으로 권한이 끊기는 피해와 복구 부담이 커집니다. B안은 검토·감사 가능한 결정 경계를 유지하는 대신, 후속 운영자가 처리하기 전까지 대응이 지연될 수 있습니다.
- 기존 인증·세션·메모 API·DB 정책은 이번 단계에서 변경하지 않았습니다. 운영 사건 전달, 탐지 실행, 회수 제안 처리의 연결은 구현하지 않았습니다.

### 로컬 테스트 기록

다음은 로컬 가상 사건 및 자동 테스트 결과이며 실제 운영 탐지·권한 회수나 심판 판정의 증거가 아닙니다.

- `npm.cmd run detect:test`: 가상 사건 6개 통과
- `npm.cmd test`: 기존 프로젝트 테스트 19개 통과
- 추가 경계 테스트 4개 통과(일회성 수동 실행): GET 120건 + POST 1건은 `observe`, 시간 역순 GET 121건은 `propose_revocation`, 정확히 600초 범위의 GET 121건은 `propose_revocation`, 600,001밀리초 범위의 GET 121건은 `observe`
- 운영 메모 5건의 이번 단계 재검증은 **미실행**입니다.

### 구현 범위와 한계

- `detect(events)`는 로컬 연습용 사건을 처리합니다. 운영 반 엔진에서 사건을 수집·검증해 이 함수에 전달하는 연결은 구현되지 않았습니다.
- `propose_revocation`은 제안일 뿐입니다. 운영 계정·기기·세션에 대한 실제 회수나 차단은 구현되지 않았습니다.
- 9단계 심판 최종 점수는 사용자가 확인한 **100/100점**입니다. 로컬 테스트 결과와 구분한 심판 결과 기록입니다.

### 재현 방법

Windows에서 다음 명령을 실행하세요.

```shell
npm install
npm.cmd run detect:test
npm.cmd test
node --check src/detect.mjs
```

새 환경에서 `npm install`의 성공 여부는 아직 검증하지 않았습니다. 탐지 연습은 120건 정상, 121건 초과 제안, 사용자별 분리, 10분 밖 사건 분리를 확인합니다. 위 네 가지 추가 경계 사례는 일회성 수동 실행이며 별도 테스트 파일로 저장하지 않았습니다.

### 포트폴리오 기록

- **설계 원칙:** 탐지와 집행을 분리하고, 부작용 없는 회수 제안 경계를 둡니다.
- **AI Agent 확장 방향:** 향후 Agent가 탐지 결과를 근거·대상과 함께 설명하고 승인 요청을 작성하도록 확장할 수 있습니다. 운영 사건 연결, 사람의 승인 절차, 실제 권한 회수는 현재 구현이 아닙니다.

**면접 예상 질문:** “121건을 탐지하면 실제 세션을 바로 끊나요?”
**답변:** “아닙니다. 이 단계는 계약된 세 필드로 사용자별 조회량을 계산해 `propose_revocation`을 반환할 뿐입니다. 운영 사건 전달과 회수 집행은 연결하지 않았고, 오탐 피해를 줄이기 위해 탐지 결과와 권한 변경을 분리했습니다.”

## 10단계 · 백업에서 자료실을 되살립니다

### 제작 1 — 정책 스냅샷과 무결성 검증

#### 해결 과제와 목표

정책 파일이 실수나 변조로 달라졌을 때 기준 버전과 비교할 수 있도록 파일 기반 스냅샷과 SHA-256 검증을 마련했습니다. 이 제작의 목표는 정책 원본을 보존하고 사본의 바이트 무결성을 확인하는 것이며, 운영 정책이나 Supabase DB를 변경하는 것이 아닙니다.

#### 설계 결정

- **A안(파일 기반 정책 스냅샷)**을 선택했습니다. 네 정책 파일을 커밋 기준으로 바이트 그대로 보관하고 manifest의 길이·SHA-256과 대조하므로, 정책 변경 전후를 파일 단위로 확인할 수 있습니다. 제작 1은 백업과 검증까지였고, 선택 복원은 제작 2에서 격리 사본에 한해 추가했습니다.
- **B안(정책별 복원 모듈)**은 각 정책을 별도 로직으로 재생성·복원하는 방식입니다. 정책 형식마다 복원 코드가 필요하고 구현과 복원 규칙이 어긋날 수 있습니다. A안은 원본 파일 바이트를 보존하며, 실제 작업 트리나 운영 정책에 직접 적용하지 않고 격리 사본에서 선택 복원합니다.
- SHA-256은 원본 바이트의 차이를 검출하는 데 사용합니다. 다만 해시와 manifest가 함께 교체되면 해시만으로 manifest의 진위를 증명할 수 없습니다. manifest 자체의 서명 또는 별도 보호는 후속 보완 사항입니다.

#### 백업 대상과 흐름

기준은 9단계 최종 커밋 `d7a6df6cb580905280dec5b1e09c0174c9599cc2`이며, 대상은 다음 네 파일입니다.

- `src/decider.mjs`
- `src/resource-access.mjs`
- `aleph.config.json`
- `docs/DECIDER_REQUEST.md`

백업 생성은 지정 커밋의 Git blob을 바이트 단위로 읽어 저장소 외부의 새 디렉터리에 기록하고, `manifest.json`에 기준 커밋 SHA와 파일별 상대 경로·바이트 길이·SHA-256을 기록합니다. 저장 직후 디스크의 네 파일을 다시 읽어 원본 및 manifest와 대조합니다. 기록된 검증 결과는 네 파일 모두 성공(4/4)이며, `src/decider.mjs`는 별도 `sha256sum` 결과도 백업 해시와 일치했습니다.

백업 사본은 저장소 외부에 보관하며 Git에 커밋하지 않습니다. 백업 생성 경로는 명령 인자로 지정하고 저장소 경로를 하드코딩하지 않습니다.

#### 격리 변조 검증

실제 정책 파일과 검증된 백업은 변경하지 않았습니다. OS 임시 디렉터리의 시험용 사본에서 `src/resource-access.mjs`의 `contractStatus` 문자열 한 곳만 합성 문자열로 바꾸고 unified diff를 확인했습니다. 시험 사본의 SHA-256이 manifest와 달라지는 것을 확인했고, 시험 후 작업 트리 원본과 백업 파일이 불변임을 재검증했습니다. 예상된 해시 불일치는 변조 탐지 성공으로 기록했습니다.

#### 제작 1 테스트 및 재현 방법

제작 1에서 기록한 로컬 결과:

- `npm run policy:test`: 4/4 통과
- `npm test`: 19/19 통과
- 백업 사본 네 파일의 SHA-256 재검증: 4/4 성공
- 격리 변조 사본의 예상 해시 불일치 탐지 및 원본·백업 불변 확인: 성공

이 제작 1 기록은 로컬 파일 검증이며 운영 Supabase 정책이나 실제 복원 성공을 증명하지 않습니다. 재현 시 본인 환경의 저장소 외부 절대 경로를 변수로 지정해 사용하세요.

PowerShell:

```powershell
$env:POLICY_BACKUP_DIR = "<저장소 외부의 새 절대 경로>"
npm run policy:backup -- "$env:POLICY_BACKUP_DIR"
npm run policy:simulate -- "$env:POLICY_BACKUP_DIR"
npm run policy:test
npm test
```

Git Bash:

```bash
export POLICY_BACKUP_DIR="<저장소 외부의 새 절대 경로>"
npm run policy:backup -- "$POLICY_BACKUP_DIR"
npm run policy:simulate -- "$POLICY_BACKUP_DIR"
npm run policy:test
npm test
```

새 백업을 만들 때는 존재하지 않는 디렉터리를 지정해야 합니다. 검증된 백업 사본은 공개 Git 저장소에 추가하지 마세요.

#### 구현 범위와 한계

- 현재 구현 범위는 네 정책 파일의 백업 생성·SHA-256 검증, 격리 시험 사본의 변조 탐지, 시험 정책 한 파일의 선택 복원까지입니다.
- 복원 적용은 격리된 로컬 시험 정책에만 수행합니다. 실제 작업 트리의 정책 파일이나 운영 정책을 복원하지 않았습니다.
- 메모 `POST` 복원 기능, 운영 DB 정책 백업·복원, 감사 이력 저장은 아직 완료되지 않았습니다.
- 운영 Supabase의 현재 RLS 정책은 **미확인**입니다. 로컬 마이그레이션 파일만으로 운영 DB 상태를 단정하지 않습니다.
- 9단계 조회 탐지는 로컬 가상 사건을 처리하며 운영 반 엔진의 사건 전달과 실제 계정·세션·기기 권한 회수는 미연동 상태입니다.

### 제작 2 — 격리 시험 정책 선택 복원

#### 목표와 설계 결정

변조된 시험 정책 사본을 검증된 백업의 바이트로 되돌리는 절차를 구현했습니다. **A안(격리된 시험 정책만 선택 복원)**을 택해 실제 작업 트리·검증된 백업·운영 정책을 변경하지 않습니다. 작업 트리를 직접 복원하는 방식은 경로 실수나 잘못된 승인으로 현재 작업 내용을 덮어쓸 수 있으므로 복원 경계를 시험 디렉터리 하나로 제한했습니다.

허용 대상은 시험 폴더의 `src/resource-access.mjs` 한 파일입니다. 다른 정책 사본과 시험 메타데이터는 유지하며, 기준은 제작 1과 같은 커밋 `d7a6df6cb580905280dec5b1e09c0174c9599cc2`입니다.

#### 준비·미리보기·적용 흐름

1. `prepare`는 백업 manifest, 기준 커밋, 네 파일의 바이트 길이와 SHA-256을 확인한 뒤 새 격리 폴더에 정책 사본을 만듭니다. 시험 대상 한 곳만 합성 표식으로 변조하고 전용 메타데이터를 기록합니다.
2. `preview`는 백업과 시험 폴더 구조·내용을 다시 검증합니다. 기준 커밋, 대상 경로, unified diff의 변경 줄, 백업 원본 SHA-256과 현재 시험 파일 SHA-256을 출력하며, 현재 시험 해시는 승인 확인값으로 제공합니다. preview는 파일을 변경하지 않습니다.
3. 명시적인 `apply` 명령에 승인 확인 SHA-256을 전달해야 합니다. 승인값이 없거나 현재 시험 대상 해시와 다르면 적용을 거부합니다. preview 뒤 대상이 바뀐 경우도 거부하며, 복원 후에는 이전 승인 해시가 더 이상 현재 파일과 일치하지 않아 재사용이 거부됩니다.
4. 적용 시 검증된 백업의 원본 바이트를 시험 폴더 안의 임시 파일에 기록해 검증한 다음 대상 한 파일만 교체합니다. 적용 후 길이·SHA-256을 manifest와 대조하고, 다른 시험 파일·메타데이터, 백업, 작업 트리의 불변성을 검사합니다.

#### 제작 2 검증 결과

- `prepare`: PASS
- `preview`: PASS — 복원 대상과 변경 범위 및 전후 해시를 확인
- `apply`: PASS — 격리 시험 폴더의 `src/resource-access.mjs`만 복원
- 복원 대상 SHA-256이 검증된 백업 manifest와 일치했고, 별도 Git Bash `sha256sum` 검사도 일치
- `npm run policy:test`: **10/10 PASS, 실패 0**
- 테스트에서 preview의 무변경, 승인 누락·불일치 거부, preview 이후 대상 변경 거부, 단일 파일 복원, 다른 사본 보존, 승인 재사용 거부를 확인
- 복원 후 로컬 정책 분류의 기존 허용 후보·거부 후보 사례가 유지됨. 이는 로컬 분류 결과이며 실제 운영 API 차단을 뜻하지 않음
- `npm test` 19/19 PASS는 제작 1 단계에서 확인한 결과입니다. 제작 2 최신 코드 이후에는 재실행하지 않았습니다.

검증은 격리된 로컬 파일을 대상으로 했습니다. 실제 Vercel API 정책, 운영 Supabase RLS 및 DB는 복원하거나 검증하지 않았습니다. 영속 감사 기록 저장소는 확인되지 않았으며, 감사 이력 저장을 구현했다고 보지 않습니다.

#### 재현 명령 예시

아래 경로는 사용자 환경에서 정한 저장소 외부 절대 경로로 바꾸고, 승인 해시는 바로 앞의 `preview` 출력값을 사용하세요. 예시는 문서화이며 제작 2 이후 테스트 재실행을 의미하지 않습니다.

```powershell
$backup = "<검증된 백업의 절대 경로>"
$test = "<별도 격리 시험 폴더의 새 절대 경로>"
node scripts/policy-snapshot.mjs prepare "$backup" "$test"
node scripts/policy-snapshot.mjs preview "$backup" "$test"
node scripts/policy-snapshot.mjs apply "$backup" "$test" "<preview 승인 SHA-256>"
npm run policy:test
```

#### 잔여 위험과 다음 단계

- SHA-256은 바이트 차이를 탐지하지만, manifest와 파일이 함께 교체되면 manifest의 진위를 단독으로 보장하지 않습니다.
- apply는 교체 직전 승인된 해시를 다시 확인하지만 확인과 교체 사이의 동시 변경을 완전히 차단한다고 보장할 수는 없습니다.
- **제작 3:** 시험 계정 B의 메모 한 건 `POST` 복원은 미구현입니다.
- **제작 4:** 회귀 테스트 작업은 미구현입니다.

**포트폴리오·면접 포인트:** 복원 대상을 격리하고 경로·manifest·해시·명시적 승인값을 단계마다 검증해, 복구 기능의 편의성과 운영 데이터 보호를 분리했습니다. “해시가 같으면 무조건 안전한가?”에는 “아니며, manifest의 진위와 TOCTOU 위험이 남아 있어 서명·안전한 저장소 잠금 같은 추가 통제가 필요합니다”라고 설명할 수 있습니다.

#### 다음 제작 기록

- **제작 2:** 구현 및 로컬 검증 기록 완료. 운영 정책·DB 복원은 수행하지 않았습니다.
- **제작 3:** 미구현 — 시험 계정 B의 메모 한 건 `POST` 복원.
- **제작 4:** 미구현 — 회귀 테스트.
- **추가 테스트·심판 결과:** 실행 또는 확인 후 실제 결과만 기록합니다.

## 시작 틀의 자동 처리

`vercel.json`은 정적 결과물 `public`과 `api/`의 서버 함수를 배포합니다. `npm run build`는 1단계 이후 설정에서도 동작하며, Vercel이 제공하는 저장소 소유자·이름, 커밋 SHA, 배포 URL을 검증해 `public/aleph.json`을 계속 생성합니다. 검증 정보가 없으면 빌드가 실패하므로 빈 주소를 내보내지 않습니다. `aleph.json`만으로 저장소 소유권이나 방어 성공을 인정하지 않습니다.

Vercel 프로젝트의 **Settings → Environment Variables**에 `SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY`, `SUPABASE_SECRET_KEY`를 설정하세요. 실제 값을 저장소, 브라우저 코드, API 응답, 로그에 기록하지 마세요. 두 Supabase 키는 서버 함수에서만 사용하며, `SUPABASE_SECRET_KEY`는 메모 데이터베이스 요청에만 사용합니다.

테스트는 `npm.cmd test`로 실행하고, 로컬 정적 빌드는 `npm.cmd run build -- --local`로 확인합니다. 로컬 빌드는 `/aleph.json`을 만들지 않으며, Vercel 서버 함수 실행이나 배포를 증명하지 않습니다. `npm.cmd run bundle`의 비로그인 `/api/notes` 요청은 학생의 자기 점검이며 심판 판정이 아닙니다.

## 다음 단계의 코딩 도구에 전달할 규칙

[AGENTS.md](AGENTS.md)를 먼저 읽히고 한 번에 한 제작 단위만 요청하세요. 이후 정책 규칙은 해당 단계 원고와 계약에 맞춰 추가합니다. 비밀번호·토큰·서버 전용 키·실제 학생 기록을 코드, Git, 제출 묶음에 넣지 않습니다.

`src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 반 엔진이나 운영 심판의 결과가 아닙니다. 1단계 이후 제출 묶음 계약 `aleph.defense.submission.v2`는 `scripts/bundle.mjs`에 남아 있으며, 코딩 도구가 해당 단계의 최신 배포 주소와 Git 원격을 맞춘 뒤 사용합니다.

## 10단계 복구 구현 추가 기록

현재 로컬 구현에는 서명 검증이 끝난 비공개 백업을 읽고, student 인증 사용자 자신의 메모만 복구하는 내부 handler `POST /api/notes/restore`가 추가되었습니다. 이 handler의 내부 요청 형식은 `targetId`, `backupVersion`이며, 기존 행이 백업과 다르면 그 현재 상태를 명시적으로 승인하기 위해 `approvedCurrentTitle`과 `approvedCurrentContent`도 함께 요구합니다. 이 승인값은 API 처리 중 현재 DB 상태와 일치하는지 검사하고, 응답이나 로그에 포함하지 않습니다. API는 백업 원문을 응답하지 않습니다.

Vercel 서버 함수의 실제 경로는 `POST /api/notes/restore`이며, `aleph.config.json`의 `restoreRoute`는 `"POST /api/notes/restore"` 형식의 문자열로 기록합니다. 이 메타데이터는 `allowedRoutes`를 변경하거나 인증을 우회하지 않습니다. 요청은 검증된 student 계정의 `Authorization: Bearer …` 또는 `__Secure-aleph_access` HttpOnly 세션 쿠키로 인증하며, 쿠키 인증은 Origin/CSRF 검사를 통과해야 합니다. JSON 본문은 다음 형식입니다.

```json
{
  "targetId": "<메모 UUID>",
  "backupVersion": "<백업 버전>",
  "approvedCurrentTitle": "<현재 제목>",
  "approvedCurrentContent": "<현재 본문>"
}
```

`approvedCurrentTitle`과 `approvedCurrentContent`는 기존 메모가 백업과 다를 때만 필요하며 둘 다 함께 보내야 합니다. 기존 메모가 없거나 백업과 이미 같으면 두 필드를 생략합니다. 위 값은 형식 예시이며 실제 메모 ID·내용을 문서나 로그에 복사하지 마세요.

DB RPC migration은 `learning_notes`의 기존 ID·소유자·제목·본문을 잠금 및 조건부 변경으로 재확인하고, 삭제 행은 원래 ID로 insert-if-absent 합니다. ID 충돌은 덮어쓰지 않으며 결과와 최소 감사 정보만 기록합니다. 현재 스키마에는 `created_at`이 있으나 기존 백업·서명 형식에는 포함되지 않으므로 삭제 복구 시 DB 기본값을 사용합니다.

위 경로·요청 형식은 프로젝트의 내부 구현 계약일 뿐 **공식 심판 복구 API의 route·payload·호출자 계약으로 확인되지 않았습니다**. `restoreRoute`는 내부 경로 메타데이터이며 기존 1~9단계의 `allowedRoutes` 및 정책은 그대로 유지합니다. 심판이 이 경로를 호출한다고 가정하거나 공식 호환을 주장하지 마세요.

로컬 실행과 운영 준비:

- 전체 저장소 테스트: `npm.cmd test` — `test/`의 자동 테스트 전체 실행
- 정적 빌드: `npm.cmd run build -- --local`
- Supabase private bucket `note-backups`는 존재하고 Vercel의 `NOTE_BACKUP_BUCKET` 설정도 등록되어 있습니다. `NOTE_BACKUP_TRUSTED_PUBLIC_KEYS_JSON` 및 기존 서버 전용 Supabase 설정은 승인된 서버 설정 화면에서만 관리하며 실제 값을 코드나 로그에 복사하지 않습니다.
- Supabase migration 적용, Storage 접근 정책 검증, 운영 공개키 등록, 실제 메모 백업/복구, Vercel 배포 및 심판 검증은 아직 수행하지 않았습니다. 이번 구현의 가짜 DB/Storage 테스트는 PostgreSQL 또는 운영 환경 통합 검증이 아닙니다.
- 미완료 운영 작업은 다음 세 묶음입니다.

1. 공식 심판의 route·payload·호출자 계약을 확인하고, DB 권한/RLS 및 migration을 검토·승인한 뒤 운영 RPC를 통합 검증합니다. Migration은 아직 적용하지 않았습니다.
2. 승인된 운영 설정에서 Ed25519 개인키를 안전하게 보관하고 공개키 공급·회전 및 private Storage 접근 정책을 구성·검증합니다. 운영 키 설정은 미완료입니다.
3. 별도 승인 후 B 메모 백업을 생성·검증하고, 실제 환경에서 회귀 및 복구 시험을 수행합니다. 운영 B 백업·복구와 배포는 미실행입니다.

### 최종 정리 진행 기록

현재 확정 가능한 상태와 검증 순서입니다. 아래 로컬 결과는 심판 판정이나 실제 B 메모 복원 결과가 아닙니다.

1. **공식 제작 1 — 로컬 정책 스냅샷:** `npm.cmd run policy:test`에서 10/10 PASS. 기준 정책 사본 해시, 시험 사본 변조 diff, 누락·변조 시 중단, 원본 및 백업 보존을 격리 테스트로 확인했습니다.
2. **공식 제작 2 — 시험 정책 복원:** 같은 10개 테스트에서 preview/승인값 확인, 승인 누락·오류·미리보기 후 변경 거부, 격리 사본의 단일 파일 복원과 다른 파일 보존을 확인했습니다. 실제 운영 정책은 변경하지 않았습니다.
3. **공식 제작 3 — B 가상 메모 백업/복원:** 복원 대상은 시험 계정 B의 가상 메모 중 `notes[0].id`로 지정한 한 건입니다. 실제 UUID·제목·본문은 Git, README, 로그에 기록하지 않습니다. 복원 전 비공개 백업을 다시 검증하고 지정 ID, B 계정 `owner_id`, 제목·본문 SHA-256 해시가 검증된 사본과 모두 일치하며 현재 상태도 예상한 경우에만 진행합니다. 어느 값이든 다르거나 예상 밖 현재 상태가 있으면 즉시 중단합니다. 지정 메모 한 건만 조건부 복원하며 다른 메모와 기존 감사 기록은 변경·삭제하지 않습니다. 복원 후 같은 ID·owner·내용 해시를 백업과 다시 비교하고 신규 감사 기록을 확인합니다. 실제 확인 결과는 운영 DB 비공개 백업 1건의 원본 일치와 `restore_learning_note`의 `no_change`(Rollback)뿐입니다. **변조된 B 메모의 실제 복원과 서명된 Storage 기반 POST 복원은 미실행**입니다.
4. **공식 제작 4 — 회귀 기록:** 복원 전 확인 결과:
   - 로컬 테스트 `npm.cmd test`: 299/299 통과.
   - `npm.cmd run decider:test`: 가상 요청 4건 통과.
   - `npm.cmd run detect:test`: 가상 사건 6건 통과.
   - `npm.cmd run policy:test`: 10/10 통과.
   - 로컬 빌드 성공, 배포 상태 Ready.
   - 운영 비로그인 `GET /api/notes`와 `POST /api/notes/restore`: HTTP 401.

   복원 후에는 다음 순서로 시험해야 합니다. **세 항목 모두 미실행**이며 PASS로 간주하지 않습니다.
   1. 인증된 정상 A/B 사용자의 자기 메모 조회와 허용 요청.
   2. 비로그인 접근, 타인 소유 메모 접근, 미등록 기기, step-up 미충족, 금지 경로 등 1~9단계 금지 요청의 거부.
   3. 다른 메모 불변 및 기존 감사 기록 보존, 신규 복원 감사 기록 확인.

복구 내부 경로는 `POST /api/notes/restore`이며 `aleph.config.json`의 `restoreRoute` 문자열에 기록합니다. 이는 프로젝트가 정한 내부 구현이며 **심판의 route·호출자·JSON 계약으로 확인되지 않았습니다**. 기존 `allowedRoutes`와 인증 정책은 보존하며, 공식 심판 자료에서 계약을 확인하기 전에는 심판이 이 경로를 호출한다고 가정하지 마세요.

복구 대상 ID는 이 README, 소스, 테스트 fixture, 터미널 기록, Git, 제출 묶음 또는 채팅에 쓰지 않습니다. 권한 있는 계정에서 확인한 뒤 학원이 승인한 암호화 비밀 저장소에만 임시 보관하고, 요청 시 명령행 인자나 환경변수 대신 승인된 비밀 입력 경로를 사용하세요. 작업 후 임시 기록을 폐기하고 B 메모의 ID·제목·본문을 로그에 남기지 마세요.

**미완료:** 공식 심판 요청 계약 및 DB migration/RPC 운영 검증, 운영 Ed25519 키와 Storage 정책 설정, 승인된 B 백업·실제 복구 검증은 아직 수행하지 않았습니다. 실제 테스트를 하지 않은 항목을 통과로 기록하지 않습니다.

## 11단계 · 기기 승인 화면 (제작 1·2)

제작 1의 manifest·오프라인 안내·연결 표시와 제작 2의 브라우저 fail-closed UI를 유지합니다. `POST /api/device/registration-options`와 `POST /api/device/registration-verify`가 WebAuthn 등록을 처리하고, 등록된 자격 증명은 `pending`으로 저장됩니다. `POST /api/device/challenge`와 `POST /api/device/verify`는 일회용 challenge/assertion으로 상태를 확인합니다. 승인 상태가 `approved`인 자격 증명의 유효한 assertion이 확인된 경우에만 `/api/notes`, `/api/notes/{id}`, `/api/notes/restore`가 메모 행에 접근합니다. 기존 Supabase Auth·HttpOnly 쿠키·CSRF 검사와 `owner_id` 필터는 유지됩니다. 거부·회수·미등록·검증 오류는 거부합니다.

`GET /api/device/admin`은 대기 요청만 반환하고 `POST /api/device/admin`은 승인·거부·회수를 처리합니다. 두 관리자 동작 모두 서버에서 Supabase 사용자 UUID가 `DEVICE_APPROVAL_ADMIN_USER_IDS` 허용목록에 있는지 확인합니다. 이 환경변수는 Vercel에 저장 완료했고, 운영에서 실제 WebAuthn 등록과 관리자 API 승인 동작을 직접 확인했습니다. 심판 판정은 **미확인**입니다. 등록 UI는 사용자의 인증기에서 공개키 증거를 받고, 개인키는 인증기 밖으로 내보내거나 웹 저장소에 저장하지 않습니다. WebAuthn은 승인된 인증 자격 증명의 소유 증거이며, 동기화형 패스키일 수 있어 물리 기기의 고유성이나 복제 불가를 보장하지 않습니다.

보호 API 요청은 assertion용 WebAuthn challenge 발급 시 HTTP method, 정규화한 경로·query, 정규화한 JSON 본문 SHA-256을 함께 저장합니다. assertion 검증 시 현재 요청의 동일 값이 DB에 저장된 값과 모두 일치해야 challenge가 원자적으로 소비됩니다. 누락·변경·만료·재사용은 거부됩니다.

**정규화 규칙:** method는 ASCII 대문자로 바꿉니다. target은 origin과 fragment 없이 `/`로 시작해야 하며, 경로 각 segment를 percent-decode 후 RFC 3986 방식으로 다시 인코딩합니다. 점 segment, encoded slash/backslash, 중복 slash는 거부하고 마지막 slash 하나는 제거합니다. query는 URLSearchParams 규칙(`+`는 공백)으로 decode한 뒤 key, value 순으로 정렬하고 모든 항목을 `key=value` 형식으로 RFC 3986 인코딩해 연결합니다. 본문이 없으면 `body_present=false`, digest는 NULL입니다. 본문이 있으면 JSON 객체 키를 재귀적으로 사전순 정렬하고 배열 순서는 유지한 canonical JSON을 UTF-8로 인코딩해 소문자 hex SHA-256을 계산합니다. JSON null은 본문 없음과 구분되며 비유한 수, undefined, 비JSON 값은 거부됩니다.

**운영 상태:** [device-approval migration](./supabase/migrations/20261104111700_device_approval.sql)을 운영 DB에 적용했고 신규 테이블 2개 생성을 확인했습니다. 기존 메모 5건과 감사 기록 0건이 유지됨을 확인했으며, `DEVICE_APPROVAL_ADMIN_USER_IDS` 환경변수도 Vercel에 저장 완료했습니다. 운영에서 A 계정으로 WebAuthn 등록 뒤 `pending` 상태를 거쳐 관리자 API(`POST /api/device/admin`)로 승인했고, 승인 뒤에만 A 메모 4건이 표시되는 것을 직접 확인했습니다. 승인 전에는 메모가 표시되지 않았고 B 계정 메모는 보이지 않았습니다. 앞서 `POST /api/device/registration-options`가 503을 반환한 원인은 DB 함수 정규식의 반복 상한 `{20,256}`이 PostgreSQL 상한 255를 넘어 발생한 오류 2201B였으며, 상한을 `{20,255}`로 고치는 [수정 migration](./supabase/migrations/20261104140500_fix_device_challenge_regex.sql)을 추가한 뒤 해결을 확인했습니다. 서명 규격의 공식 심판 호환성은 **미확인**입니다.

검증: 자동 테스트는 WebAuthn 검증기를 모의해 등록 대기, 승인·거부·회수, 오류 시 거부, 인증 없이 메모 API 직접 호출 차단, 기존 인증·CSRF·A/B 소유권·복구 회귀를 확인합니다. 이 결과는 실제 인증기·운영 DB·공식 심판 판정을 뜻하지 않습니다.

로컬 `npm test` 실행 결과: 346/346 통과, 실패 0. 운영 등록·승인은 직접 확인했고, 심판 판정은 **미확인**입니다.

## 12단계 · 탈환 작전실

이 절은 12단계 저장점 커밋 기준이며, 직전 운영 배포 `cfdf221`에서 실측했습니다.

### 출처와 책임 구분

| 구분 | 범위 |
| --- | --- |
| 제공 엔진 | ALEPH SDP 엔진(운영 측 제공). 심판 접수(`judgeIssuer`), 운영 반 탐지 사건 전달과 접속 회수 집행은 제공 엔진의 몫이며 이 저장소에서 구현하거나 시험하지 않았습니다. |
| 학생 작업 | 판정기 [src/decider.mjs](./src/decider.mjs)(`RULE_IDS` 3종), 탐지 규칙 [src/detect.mjs](./src/detect.mjs)(가상 사건 연습, 운영 미연결), 접속 앱([api/](./api/), [public/](./public/): 로그인·CSRF·소유권·기기 승인·요청 결합 서명·작전실), 자료실(Supabase `learning_notes`, 복구 함수, 마이그레이션). |

### 작전실

`GET /api/ops/summary`는 관리자 허용목록만 허용하는 읽기 전용 API입니다. 판정기 규칙(코드 기준), 탐지(미연결), 기기 상태 건수(실측), 복구 결과 건수(실측)를 보여 줍니다. 복구 건수는 `learning_note_restore_audit_summary` 함수로 건수만 조회합니다. 영역별 조회 실패는 `확인 실패`로 표시합니다. 메모 본문·UID·credential은 응답하지 않습니다.

### 운영에서 발견한 문제

처음 배포에서 503이 발생했습니다. 원인은 감사 테이블에 SELECT 권한이 없었던 것(`has_table_privilege` 결과 `false`)입니다. 10단계의 INSERT 전용 설계를 유지하기 위해 테이블 권한은 바꾸지 않고, 건수만 돌려주는 `SECURITY DEFINER` 함수(`service_role`만 실행 가능)를 추가했습니다. 자동 테스트는 모의 DB를 사용하므로 이 문제를 찾지 못했고, 운영 실측으로 발견했습니다.

### 재현 순서

1. 설치: `npm install`
2. 시험: `npm test` (모의 DB·모의 WebAuthn 사용, 운영 확인 아님)
3. 자기 점검: `npm run attack:table` (운영에 비로그인 요청만 보냄)
4. 실행(배포): `main`에 push하면 Vercel이 배포합니다. 필요한 환경변수 이름은 `SUPABASE_URL`, `SUPABASE_SECRET_KEY`, `DEVICE_APPROVAL_ADMIN_USER_IDS`입니다. 값은 Vercel 설정 화면에만 입력하고 저장소에 넣지 않습니다.
5. DB 준비: [supabase/migrations/](./supabase/migrations/)의 SQL을 파일 이름 순서대로 적용합니다.
6. 중지: Vercel 프로젝트를 일시 중지(Pause)하거나 직전 배포로 롤백합니다.
7. 복구: 문제 배포는 Vercel에서 직전 READY 배포로 롤백합니다. 복구 감사 요약 함수는 `DROP FUNCTION public.learning_note_restore_audit_summary();`로 되돌립니다(데이터 영향 없음). 메모 복구는 10단계 절차(`POST /api/notes/restore`)를 따릅니다.

실측 기록은 [docs/R12_MEASUREMENTS.md](./docs/R12_MEASUREMENTS.md)에 있습니다. 41종 시험은 **심판 판정 미확인**입니다.

### 한계

탐지 사건은 운영 미연결이며, 회수 재전송은 되돌릴 수 없어 운영에서 시험하지 않았습니다. 로그인이 필요한 금지 요청 중 일부는 미실행입니다.

## 보너스 xdr-01 · 무차별 로그인 공격을 잡아 냅니다

Wazuh 모양 연습 경보(`xdr/fixtures/brute-force.json`, 28건)에서 로그인 실패를 모아 판단하는 모듈입니다. 근거는 MITRE ATT&CK T1110입니다.

- `xdr/brute-force/read-alerts.mjs`: 확인용 읽기 모듈. 시각·주소·계정·규칙 수준·설명만 출력하고 비밀값처럼 보이는 값은 가립니다.
- `xdr/brute-force/patterns.json`: `same_source_failure_burst`(T1110.001), `password_spraying`(T1110.003), `low_volume_failures`(T1110) 세 패턴과 근거.
- `xdr/brute-force/decide.mjs`: import·파일 입출력·외부 호출 없이 `decide(alert)`가 `{action, confidence, reason}`을 돌려줍니다. 0.85 이상 `block`, 0.5 이상 `alert`, 그 아래 `record`. 실패 뒤 성공이 있거나 규칙 수준이 10 미만이면 차단까지 가지 않습니다.
- `xdr/brute-force/respond.mjs`: `block` 결과만 만료 시각(근거 경보 +1시간)과 근거 경보 번호가 붙은 거부 규칙(`deny-rules.json`)으로 만들고, 정상 이벤트가 나온 주소는 제외합니다. `block`·`alert`는 `xdr/alerts.log`에 한 줄씩 쌓습니다(커밋 제외). 판정기 앞에 붙일 `isSourceBlocked()` 확인 부품을 내보내며, `src/decider.mjs`의 기존 규칙은 바꾸지 않았습니다.

다시 실행:

```shell
node xdr/brute-force/read-alerts.mjs
npm.cmd run xdr:run -- brute-force
node xdr/brute-force/respond.mjs
```

로컬 결과: `block` 10 · `alert` 9 · `record` 9, 정상 이벤트 차단 0건. 시험 경보를 다시 흘리면 명확한 공격 10건만 막히고 나머지 18건은 통과합니다. 판정기 계약(`docs/DECIDER_REQUEST.md`)에는 출발 주소 항목이 없어, 거부 규칙은 실제 판정기 요청에 아직 연결되지 않았습니다. 이 결과는 로컬 연습이며 심판 판정이 아닙니다.

## 보너스 xdr-02 · 웹 주입 공격을 잡아 냅니다

MITRE ATT&CK T1190을 근거로 가상 웹 경보 26건을 분류하는 연습입니다. 요청 URL의 `doc-` 패턴 표식뿐 아니라 같은 주소의 반복 횟수(`data.count`)와 규칙 수준(`rule.level`)을 함께 사용합니다. `sql`, `select`, `script`, `up` 같은 단어 하나나 수업 이름만으로는 공격으로 판정하지 않습니다.

- `xdr/web-injection/read-alerts.mjs`: 가상 경보를 읽고 비밀값처럼 보이는 값은 출력하지 않습니다.
- `xdr/web-injection/patterns.json`: SQL 구문, script 표식, 반복 경로 이탈, 명령 구분자 패턴과 T1190 근거를 기록합니다.
- `xdr/web-injection/decide.mjs`: 파일·네트워크 접근 없이 `decide(alert)`가 `{ action, confidence, reason }`을 반환합니다. confidence 0.85 이상은 `block`, 0.5 이상은 `alert`, 그 아래는 `record`입니다.
- `xdr/web-injection/respond.mjs`: `block` 결과만 문서용 주소의 한 시간짜리 거부 규칙으로 만들고, 같은 주소에서 `record`가 나온 경우는 규칙에서 제외합니다. `block`·`alert`만 `xdr/alerts.log`에 추가합니다.
- `xdr/web-injection/result.json`과 `xdr/web-injection/deny-rules.json`: 가상 fixture 실행 결과와 거부 규칙입니다.

다시 실행:

```shell
node xdr/web-injection/read-alerts.mjs
npm.cmd run xdr:run -- web-injection
node xdr/web-injection/respond.mjs
```

로컬 가상 결과는 `block` 7 · `alert` 0 · `record` 19이며, 정상 이벤트 wi-18~wi-26 차단은 0건입니다. 응답 연습에서는 6개 주소 규칙을 만들고 block 경보 7줄을 `xdr/alerts.log`에 추가했습니다. 이 연습은 제공 엔진의 실제 웹 요청 탐지나 접속 차단에 연결되지 않았으며, 운영 보호나 심판 판정을 증명하지 않습니다.

## 보너스 xdr-03 · 알려진 취약점 악용을 잡아 냅니다

CVE-2021-44228(Log4Shell)과 MITRE ATT&CK T1190을 근거로 가상 경보 24건을 분류하는 연습입니다. 요청 머리글(`data.useragent`)이나 요청 인자(`data.url`)에 완전한 원격 조회 구문(`${jndi:…://…}` 형태)이 있는지와 반복 횟수(`data.count`), 규칙 수준(`rule.level`)을 함께 봅니다. CVE 이름, jndi 단어, 잘린 조각만 있는 요청은 차단하지 않고 알림으로만 남깁니다. 경보 속 조회 구문은 문서용 표기입니다.

- `xdr/known-cve/read-alerts.mjs`: 확인용 읽기 모듈. 시각·주소·계정·규칙 수준·설명만 출력하고 비밀값처럼 보이는 값은 가립니다. 조회 구문이 든 url·useragent는 출력하지 않습니다.
- `xdr/known-cve/patterns.json`: 머리글·인자·양쪽 위치 조회 구문, 반복 조회, 점검 도구 흔적 + 조회 구문, 조회 구문 없는 CVE 흔적(알림 전용) 여섯 패턴과 근거.
- `xdr/known-cve/decide.mjs`: import·파일 입출력·외부 호출 없이 `decide(alert)`가 `{ action, confidence, reason }`을 반환합니다. 0.85 이상 `block`, 0.5 이상 `alert`, 그 아래 `record`. 주소 인코딩과 `${lower:j}` 같은 흔한 감추기를 풀어 비교합니다.
- `xdr/known-cve/respond.mjs`: `block` 결과만 만료 시각(근거 경보 +1시간)과 근거 경보 번호가 붙은 거부 규칙(`deny-rules.json`)으로 만들고, 같은 주소에서 `record`가 나온 경우는 제외합니다. `block`·`alert`만 `xdr/alerts.log`에 추가합니다(커밋 제외). `src/decider.mjs`의 기존 규칙은 바꾸지 않았습니다.
- `xdr/known-cve/result.json`과 `xdr/known-cve/deny-rules.json`: 가상 fixture 실행 결과와 거부 규칙입니다.

다시 실행:

```shell
node xdr/known-cve/read-alerts.mjs
npm.cmd run xdr:run -- known-cve
node xdr/known-cve/respond.mjs
```

로컬 가상 결과는 `block` 8 · `alert` 8 · `record` 8이며, 정상 이벤트 kc-17~kc-24 차단은 0건입니다. 응답 연습에서는 7개 주소 규칙을 만들고 block·alert 경보 16줄을 `xdr/alerts.log`에 추가했습니다. 이 연습은 제공 엔진의 실제 요청 탐지나 접속 차단에 연결되지 않았으며, 운영 보호나 심판 판정을 증명하지 않습니다.

## 보너스 xdr-04 · 몰래 심어진 프로그램을 찾아냅니다

MITRE ATT&CK T1543(서비스)과 T1053(예약 작업)을 근거로, 다시 켜도 남도록 심긴 프로그램을 다룬 가상 경보 24건을 분류하는 연습입니다. 서비스나 예약 작업이 있다는 사실만으로는 공격으로 보지 않고, 실행 파일 경로(`data.path`), 반복 횟수(`data.count`), 규칙 수준(`rule.level`), `rule.mitre`, 설명의 서명·친숙도 표현을 함께 봅니다.

- `xdr/persistence/read-alerts.mjs`: 확인용 읽기 모듈. 시각·주소·계정·규칙 수준·설명만 출력하고 비밀값처럼 보이는 값은 가립니다.
- `xdr/persistence/patterns.json`: 임시 폴더 실행 파일, 평소 목록에 없는 항목, 서명 없음, 서명 없는 등록 반복, 지속 수단 겹침, 검토 대상(알림 전용) 여섯 패턴과 근거.
- `xdr/persistence/decide.mjs`: import·파일 입출력·외부 호출 없이 `decide(alert)`가 `{ action, confidence, reason }`을 반환합니다. 0.85 이상 `block`, 0.5 이상 `alert`, 그 아래 `record`. 경보 id·주소·계정은 판단에 쓰지 않습니다.
- `xdr/persistence/respond.mjs`: `block` 결과만 만료 시각(근거 경보 +1시간)과 근거 경보 번호가 붙은 거부 규칙(`deny-rules.json`)으로 만들고, 같은 주소에서 `record`가 나온 경우는 제외합니다. 모든 경보가 같은 PC이고 같은 계정이 정상 경보에도 나오므로 규칙은 출발 주소로만 만듭니다. `block`·`alert`만 `xdr/alerts.log`에 추가합니다(커밋 제외). 실행할 때마다 같은 줄이 다시 쌓입니다. `src/decider.mjs`의 기존 규칙은 바꾸지 않았습니다.
- `xdr/persistence/result.json`과 `xdr/persistence/deny-rules.json`: 가상 fixture 실행 결과와 거부 규칙입니다.

다시 실행:

```shell
node xdr/persistence/read-alerts.mjs
npm.cmd run xdr:run -- persistence
node xdr/persistence/respond.mjs
```

로컬 가상 결과는 `block` 8 · `alert` 8 · `record` 8이며, 경보 설명으로 정상 이벤트로 본 ps-17~ps-24의 차단은 0건입니다. 저장소에 정답이 없어 이 건수가 정답인지는 확인되지 않았고, 패턴은 같은 경보를 읽고 작성했습니다. 응답 연습에서는 7개 주소 규칙을 만들고 실행 1회당 16줄을 `xdr/alerts.log`에 추가합니다. 규칙 만료 시각은 경보 시각 기준이라 현재 시계로는 이미 지났습니다. 판정기 계약(`docs/DECIDER_REQUEST.md`)에는 출발 주소 항목이 없어 거부 규칙은 실제 판정기 요청에 연결되지 않았습니다. 이 연습은 제공 엔진의 실제 탐지나 접속 차단을 증명하지 않으며, 심판 판정이 아닙니다.

`npm.cmd test`는 이 저장점에서 360개 중 356개 통과, 4개 실패입니다. 실패는 `attack-check` 점검 시험(`test/attack-check.test.mjs` 3개, `test/r5.test.mjs` 1개)이며 원인은 아직 확인하지 못했습니다.

## 보너스 xdr-05 · 권한 가로채기를 잡아 냅니다

MITRE ATT&CK T1068(권한 상승 악용)과 T1078(정상 계정 도용)을 근거로 가상 경보 26건을 분류하는 연습입니다. 관리자 그룹 추가는 설명 문구가 아니라 `data.group`이 정확히 `administrators`인지로, 업무 시간 밖 여부는 `timestamp`가 아니라 설명 문구로 판단합니다. 관리자 그룹 추가를 직접 다루는 MITRE 기법은 T1098.007이지만, 경보 표시와 과제 근거에 맞춰 T1078에 묶었습니다.

- `xdr/privilege/read-alerts.mjs`: 확인용 읽기 모듈. 시각·주소·계정·규칙 수준·설명만 출력하고 비밀값처럼 보이는 값은 가립니다.
- `xdr/privilege/patterns.json`: 관리자 그룹 추가, 추가 직후 명령, 처음 보는 주소의 권한 사용, 다른 계정 권한 사용, 여러 계정 추가, 빠졌다가 재추가, 업무 시간 밖 권한 사용, 검토 대상(알림 전용) 여덟 패턴과 근거.
- `xdr/privilege/decide.mjs`: import·파일 입출력·외부 호출 없이 `decide(alert)`가 `{ action, confidence, reason }`을 반환합니다. 0.85 이상 `block`, 0.5 이상 `alert`, 그 아래 `record`. 취소·실패·"없습니다"·"아닙니다"가 있으면 뚜렷한 패턴으로 치지 않습니다. 경보 id·주소·계정·시각은 판단에 쓰지 않으며, admin01·svc-lab도 이름으로 예외를 두지 않습니다.
- `xdr/privilege/respond.mjs`: `block` 결과만 만료 시각(근거 경보 +1시간)과 근거 경보 번호가 붙은 거부 규칙(`deny-rules.json`)으로 만듭니다. 차단 대상은 계정 세션(`srcuser`+`srcip`)이라 같은 계정이 평소 주소에서 접속하면 걸리지 않으며, 같은 주소에서 `record`가 나온 경우는 제외합니다. `block`·`alert`만 `xdr/alerts.log`에 추가합니다(커밋 제외). 실행할 때마다 같은 줄이 다시 쌓입니다. `src/decider.mjs`의 기존 규칙은 바꾸지 않았습니다.
- `xdr/privilege/result.json`과 `xdr/privilege/deny-rules.json`: 가상 fixture 실행 결과와 거부 규칙입니다.

다시 실행:

```shell
node xdr/privilege/read-alerts.mjs
npm.cmd run xdr:run -- privilege
node xdr/privilege/respond.mjs
```

로컬 가상 결과는 `block` 9 · `alert` 8 · `record` 9이며, 경보 설명으로 정상 이벤트로 본 pv-18~pv-26의 차단은 0건입니다. 저장소에 정답이 없어 이 건수가 정답인지는 확인되지 않았고, 패턴은 같은 경보를 읽고 작성했습니다. 응답 연습에서는 8개 세션 규칙을 만들고 실행 1회당 17줄을 `xdr/alerts.log`에 추가합니다. 규칙 만료 시각은 경보 시각 기준이라 현재 시계로는 이미 지났습니다. 판정기 계약(`docs/DECIDER_REQUEST.md`)에는 `srcuser`·`srcip` 항목이 없어 거부 규칙은 실제 판정기 요청에 연결되지 않았습니다. 이 연습은 제공 엔진의 실제 탐지나 접속 차단을 증명하지 않으며, 심판 판정이 아닙니다.

`npm.cmd test`는 이 저장점에서도 360개 중 356개 통과, 4개 실패입니다. 실패는 xdr-04와 같은 `attack-check` 점검 시험 4개이며 원인은 아직 확인하지 못했습니다.
