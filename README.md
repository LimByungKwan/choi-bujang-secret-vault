# BYTE BACK 방어전 R5 5단계 자료실

이 저장소는 브라우저의 Supabase 로그인은 유지하면서 메모 CRUD를 Vercel 서버 함수로 모은 R5 5단계 구현입니다. 실제 학생 자료, 토큰, 비밀키를 코드나 브라우저 파일에 넣지 마세요.

## 학생이 하는 일: 세 걸음

1. GitHub 계정을 만듭니다.
2. 방어전 카드의 **Deploy** 버튼을 누릅니다. Vercel에 GitHub로 로그인하고 저장소를 선택해 Deploy를 누릅니다.
3. 배포가 끝나면 화면에 나온 `https://…vercel.app` 주소를 현재 단계 카드에 제출합니다. 저장소 주소나 설정 파일은 적지 않습니다.

배포가 끝나면 `/` 화면에서 Supabase 학습 계정으로 로그인할 수 있습니다. 브라우저는 Supabase Auth 로그인·로그아웃만 직접 호출하고, 메모 자료는 `GET`·`POST /api/notes`와 `GET`·`PUT`·`DELETE /api/notes/{id}` 서버 함수를 통해 요청합니다. 서버는 `src/verify-login.mjs`로 로그인 사용자를 확인하고, 목록·단건 조회·수정·삭제는 검증된 사용자의 메모에만 적용합니다. 메모 생성 시 소유자는 서버가 검증한 사용자 ID로 설정하며 요청 본문의 `owner_id`는 사용하지 않습니다. `public/data.json`은 빌드에서 제거되며 더 이상 생성되지 않습니다.

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

이 절차는 GitHub 최신 파일과 현재 배포만 확인합니다. 옛 공개 커밋이나 이전 배포가 남아 있는 동안에는 과거 노출이 해소됐다고 쓰지 마세요. 과거 커밋과 이전 배포 주소도 별도로 확인하고, 남아 있다면 과거 노출은 계속된 것으로 취급해야 합니다.

## 시작 틀의 자동 처리

`vercel.json`은 정적 결과물 `public`과 `api/`의 서버 함수를 배포합니다. `npm run build`는 1단계 이후 설정에서도 동작하며, Vercel이 제공하는 저장소 소유자·이름, 커밋 SHA, 배포 URL을 검증해 `public/aleph.json`을 계속 생성합니다. 검증 정보가 없으면 빌드가 실패하므로 빈 주소를 내보내지 않습니다. `aleph.json`만으로 저장소 소유권이나 방어 성공을 인정하지 않습니다.

Vercel 프로젝트의 **Settings → Environment Variables**에 `SUPABASE_URL`과 `SUPABASE_SECRET_KEY`를 설정하세요. 실제 값을 저장소, 브라우저 코드, API 응답, 로그에 기록하지 마세요. `SUPABASE_SECRET_KEY`는 서버 함수에서만 사용합니다.

테스트는 `npm.cmd test`로 실행하고, 로컬 정적 빌드는 `npm.cmd run build -- --local`로 확인합니다. 로컬 빌드는 `/aleph.json`을 만들지 않으며, Vercel 서버 함수 실행이나 배포를 증명하지 않습니다. `npm.cmd run bundle`의 비로그인 `/api/notes` 요청은 학생의 자기 점검이며 심판 판정이 아닙니다.

## 다음 단계의 코딩 도구에 전달할 규칙

[AGENTS.md](AGENTS.md)를 먼저 읽히고 한 번에 한 제작 단위만 요청하세요. 이후 정책 규칙은 해당 단계 원고와 계약에 맞춰 추가합니다. 비밀번호·토큰·서버 전용 키·실제 학생 기록을 코드, Git, 제출 묶음에 넣지 않습니다.

`src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 반 엔진이나 운영 심판의 결과가 아닙니다. 1단계 이후 제출 묶음 계약 `aleph.defense.submission.v2`는 `scripts/bundle.mjs`에 남아 있으며, 코딩 도구가 해당 단계의 최신 배포 주소와 Git 원격을 맞춘 뒤 사용합니다.
