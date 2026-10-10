# Qshing Project

QR 콘텐츠를 즉시 실행하지 않고 먼저 분석하여 위험 점수와 판단 근거를 제공하는 **큐싱(QR Phishing) 예방 애플리케이션**입니다. URL뿐 아니라 전화번호, SMS, 이메일, Wi-Fi, 일반 텍스트를 구분합니다. 점수와 외부 평판은 실제 안전성을 보장하지 않습니다.

## 주요 기능

- Flutter 카메라로 QR 원본 데이터를 읽고 FastAPI에 분석 요청
- URL 구조·키워드·브랜드 사칭·Punycode 등 규칙 기반 분석과 선택적 VirusTotal 평판 조회
- 일반 텍스트 및 SMS·메일 본문에 포함된 명시적 URL과 스킴 없는 후보 분석
- 링크별 점수·사유·평판 출처·HTTPS 가정·분석 미완료 표시
- DynamoDB에 부모 QR 이력 저장, 관리자용 최신 저장 이력·통계 조회
- 결과·오류 화면 전체 본문 사용과 하단 다시 스캔하기 버튼

## 시스템 흐름

```text
QR 스캔 → Flutter: 중복 인식 차단, 카메라 중지
   ↓ POST /analyze-qr {content}
FastAPI: 공유 분석 시간 예산 시작, QR 유형·필드 파싱
   ├─ 직접 HTTP/HTTPS URL → URL 캐시 확인·규칙 버전 검증
   │                         → 필요 시 로컬 분석·VT 조회·캐시 갱신
   └─ 비URL QR → 부모 로컬 분석
                 → 분석 대상 본문 링크 선택·중복 제거
                 → 최대 3개 URL을 같은 캐시·URL 분석 경로에서 순차 분석
   ↓ 부모·성공한 포함 URL 최고 점수의 max 결합, 실패·제외 정보 정리
저장 정책과 남은 예산에 따라 DynamoDB 부모 이력 저장
   → 직접 URL 이력 저장 성공 시에만 캐시의 최초 이력 완료 표시
   ↓ 저장 성공/실패 또는 중복 생략 정보를 분석 결과에 추가
API 응답 모델 직렬화 → Flutter 결과 화면
   ↓ 하단 다시 스캔하기
이전 결과·오류·중복 방지 상태 초기화 → 카메라 스캔 대기
```

캐시와 이력은 서버에서 처리합니다. DB 저장이 실패해도 완료한 분석 결과는 반환하며, `db_saved`와 `db_error`로 저장 상태를 구분합니다. 포함 URL마다 별도 이력을 만들지 않습니다.

## 프로젝트 구조

파일명 대소문자는 아래와 같습니다. 연구 디렉터리는 공개 구조에서 제외했습니다.

```text
Qshing_project/
├─ backend/
│  ├─ app/
│  │  ├─ main.py                  # API·포함 URL 결합·이력 저장 연결
│  │  ├─ schemas.py               # 공개 응답 모델
│  │  ├─ constants.py             # 규칙·연결 정책 버전과 판정 관련 상수
│  │  └─ services/
│  │     ├─ qr_analyzer.py         # 유형 분류·구조형 파싱·후보 검증
│  │     ├─ scanner.py             # URL 점수 규칙
│  │     ├─ virustotal.py          # 리포트 조회·조건부 제출
│  │     ├─ url_cache.py           # 버전 검증·직접 URL 이력 정책
│  │     ├─ database.py            # 이력 저장·최신 목록·통계
│  │     └─ analysis_budget.py     # monotonic 공유 시간 예산
│  ├─ EMBEDDED_URL_POLICY.md
│  ├─ URL_RULESET_POLICY.md
│  ├─ ANALYSIS_TIME_POLICY.md
│  ├─ DIRECT_URL_HISTORY_POLICY.md
│  ├─ SCAN_HISTORY_READ_POLICY.md
│  ├─ test_analyze_qr.py
│  ├─ test_analysis_budget.py
│  ├─ test_direct_url_history.py
│  ├─ test_embedded_url_history.py
│  ├─ test_scan_history_reads.py
│  ├─ requirements.txt            # 운영 의존성 고정
│  ├─ requirements-dev.txt        # 공개 백엔드 테스트 의존성
│  ├─ build_lambda_package.ps1
│  └─ .env.example
├─ qr_phishing_app/
│  ├─ lib/
│  │  ├─ main.dart                # 스캔 상태·카메라 생명주기·API 요청
│  │  ├─ analysis_result.dart     # JSON 파싱·평판 상태/출처 모델
│  │  └─ analysis_result_view.dart # 결과·포함 URL 표시(main.dart의 part)
│  ├─ test/
│  │  ├─ analysis_result_test.dart
│  │  ├─ analysis_result_view_test.dart
│  │  ├─ scan_page_test.dart
│  │  └─ fixtures/analysis_responses.dart
│  ├─ android/ · ios/ · web/ · windows/ · linux/ · macos/
│  ├─ api_config.example.json
│  ├─ pubspec.yaml
│  └─ pubspec.lock
├─ .gitignore
└─ readme.md
```

백엔드는 Python·FastAPI·Pydantic·Mangum과 DynamoDB·VirusTotal 연동을 사용하며 Lambda/API Gateway 실행을 위한 구성이 있습니다. 배포 패키지 대상은 Python 3.12입니다. 앱은 Flutter·Dart와 `mobile_scanner`, `http`를 사용합니다. 실제 운영 배포·설정 상태는 이 문서로 확인한 것이 아닙니다.

## QR 분석과 판정

URL 규칙 버전은 **`RULESET_VERSION=1.2`**입니다. HTTP, IP 호스트, 길이, 단축 URL, userinfo, 인코딩·위험 패턴, Punycode 호스트, 비표준 포트 등을 검사합니다. 브랜드 사칭은 파싱한 호스트의 구체적인 브랜드 식별자를 기준으로 하며, 공식 도메인 예외도 정확한 호스트 또는 점으로 구분된 하위 도메인에만 적용합니다. 공식 도메인도 다른 위험 검사를 수행합니다. 일반 단어와 약한 행사 키워드의 점수·민감도 한계는 [URL 규칙 정책](backend/URL_RULESET_POLICY.md)을 참고하세요.

일반 텍스트는 포함 링크를 분석합니다. `SMS`, SMS colon-message, `SMSTO`, `mailto`는 **원시 필드 경계를 먼저 분리한 뒤 필요한 값을 디코딩하여 본문 링크만 분석**합니다. 수신자·메일 주소·제목·Wi-Fi SSID의 도메인을 본문 링크로 취급하지 않으며, 인코딩된 `&`, `=`, `?`로 바깥 필드 경계를 다시 나누지 않습니다.

검증된 `bit.ly/3abcde` 같은 스킴 없는 후보에는 `https://`를 가정해 기존 URL 분석·캐시 경로를 적용합니다. **실제 HTTPS 지원이나 도착지·안전성을 확인한 것이 아닙니다.** 스킴 생략 자체에는 점수를 가산하지 않으며 이메일 주소·일반 파일명·검증 제외 문자열·다른 URI 스킴을 임의로 HTTPS 주소로 바꾸지 않습니다.

명시적 HTTP/HTTPS 링크를 먼저 선택하고 후보를 합칩니다. 스킴·호스트를 소문자화한 분석 주소로 중복 제거하되 경로·쿼리 대소문자는 보존하며, HTTP와 HTTPS는 별개입니다. **실패한 시도를 포함해 최대 3개 URL을 순차 분석**합니다. 원본은 `original_url`, `original_candidates`, 분석 주소는 `analysis_url`, 가정 여부는 `assumed_https`로 반환하며, 이 메타데이터는 캐시와 분리해 요청별로 붙입니다. 기존 `extracted_urls`는 명시적 URL, `extracted_url_candidates`는 원본 후보의 의미를 유지합니다. 구조형 QR의 공개 추출 목록과 본문 분석 대상은 다를 수 있습니다.

포함 URL을 분석한 QR의 최종 점수는 **`max(parent_score, embedded_url_max_score)`**입니다. 일부 링크가 실패해도 부모 점수와 성공한 링크 결과를 보존합니다. `embedded_url_failures`는 공개 오류 코드와 대상 정보를 제공하며, 실패 또는 개수 제한 제외가 있으면 `embedded_url_analysis_complete=false`입니다. 실패 개수와 제한 제외 개수는 `analysis_flags`에서 구분합니다. 포함 URL 연결 정책 **2.0**과 비URL 점수 규칙 **2.0**은 URL 규칙 버전과 별도입니다. 상세 계약은 [포함 URL 정책](backend/EMBEDDED_URL_POLICY.md)에 있습니다.

| 최종 점수 | API status | 앱 표시 |
| ---: | --- | --- |
| 0~29 | `safe` | 낮은 위험 |
| 30~69 | `warning` | 주의 |
| 70~100 | `danger` | 위험 |

앱의 ‘낮은 위험’은 현재 확인한 정보에서 위험 신호가 적다는 뜻이며 실제 안전성을 보장하지 않습니다. 이 점수는 콘텐츠·리디렉션·실제 소유권·TLS 지원을 모두 검증한 결과가 아닙니다. 연구 당시 코드·데이터·기대값·평판 스냅샷·결과에 현재 정책을 소급 적용하지 않습니다. 각 정책 문서의 비교 기준 커밋을 연구 평가 버전으로 단정하지 않습니다.

## 외부 평판과 앱 표시

위험 점수와 외부 평판 확인 여부는 별도로 표시합니다. `vt_available`, `vt_lookup_status`는 조회 상태를, `vt_source`는 정보 출처를 나타냅니다. `cache_hit`나 재조회 사유만으로 외부 조회 성공·캐시 평판 재사용을 판단하지 않습니다.

| 상태·출처 | 의미와 표시 |
| --- | --- |
| `available` / `url_report` | 이번 요청에서 외부 리포트 조회. 리포트의 분석 시각은 조회 시각과 다를 수 있음 |
| `cached` / `cached_report` | 저장된 리포트 재사용. 최신 상태와 다를 수 있음 |
| 조회 미완료 + `cached_report` + `historical_reputation_used` | 이번 조회 실패·유예 상태와 과거 정보의 점수 사용을 함께 안내. 탐지 수는 과거 값으로 표시 |
| `lookup_failed`, `timeout`, `rate_limited`, `budget_exhausted` | 조회 실패·시간 초과·요청 제한·분석 시간 부족으로 외부 평판 미확인 |
| `report_missing` | 해당 주소의 외부 리포트 없음 |
| `submitted` / `submitted_analysis` | 분석 요청 접수. 리포트 확인 완료가 아니며 제출 후 폴링하지 않음 |
| `disabled` | 외부 평판 조회를 사용하지 않음 |
| 누락·알 수 없는 상태/출처 | 조회 상태 또는 출처 확인 불가. 탐지 수 누락을 0으로 보완하지 않음 |

`vt_available=true`이고 탐지 수가 0인 리포트와 조회하지 못한 상태는 구분합니다. 조회 실패 응답의 호환용 숫자 0은 확인된 악성 탐지 0건을 뜻하지 않습니다. 새 조회 성공을 ‘방금 검사된 최신 리포트’로 표현하지 않습니다. 필드가 없는 이전 응답은 보수적으로 표시하며, 명시적인 과거 정보 사용 또는 가용 리포트의 캐시 재사용 근거가 있는 경우만 출처를 보완합니다. `cache_miss`는 저장된 평판 재사용 근거가 아닙니다.

직접 URL과 각 포함 URL 카드에 같은 기준을 적용하며 부모 VT 수치로 자식 조회 성공을 추정하지 않습니다. 분석 대상 URL이 있고 `vt_available=false`이면 ‘외부 평판 정보 없음’, ‘현재 확인한 정보만으로 평가한 결과입니다.’를 표시합니다. 가용 여부가 누락되면 ‘조회 상태 확인 불가’이며, URL 없는 전화번호·Wi-Fi·일반 텍스트에는 평판 누락 안내를 붙이지 않습니다.

앱은 스캔 대기 → 분석 중 → 결과 또는 오류 → 다시 스캔하기로 전환합니다. 분석 중에는 중복 인식·요청을 막고 카메라를 중지합니다. 결과·오류 상태에서는 상단 제목을 유지하고 카메라를 숨겨 본문 전체를 사용하며, 결과는 스크롤하고 하단 재스캔 버튼은 별도로 유지합니다. 링크별 사유·HTTPS 가정·부분 실패·제한 제외를 표시하고, 안내에 문구와 아이콘을 함께 사용합니다. 결과를 보는 중 앱 복귀로 카메라를 재개하지 않으며, 이전 요청이나 dispose 후 응답이 새 화면 상태를 덮어쓰지 않도록 검사합니다. URL·SMS를 자동 실행하거나 결과 링크를 여는 기능은 없습니다.

## API와 저장 이력

### QR 분석 및 직접 URL 분석

`POST /analyze-qr` 요청:

```json
{"content": "QR code raw content"}
```

`POST /scan`은 `url` 필드에 명시적 HTTP/HTTPS 주소를 받습니다. 분석 응답에는 유형·점수·판정·사유·규칙 버전·평판·캐시·이력 저장 상태가 포함되며, QR 응답에는 포함 URL 결과·실패·완료 여부도 있습니다. 필드 정의는 [schemas.py](backend/app/schemas.py), 로컬 API 명세는 `/docs`에서 확인할 수 있습니다.

직접 URL 캐시의 `scan_count`는 직접 요청을 기록하며 **이력 저장 완료 상태와 별개**입니다. 캐시 사용 시 최초 이력을 저장하고, 실제 저장 성공 후에만 완료 상태를 기록합니다. 최초 저장 실패·예산 부족은 다음 직접 요청에서 재시도하며, 완료 후 같은 점수·판정의 요청은 `history_skip_reason=duplicate_unchanged`로 이력을 생략합니다. 위험도 변경은 저장하고 규칙 변경으로 위험도가 바뀌면 `ruleset_reclassified`로 저장합니다. 규칙 버전만 바뀌고 위험도가 같으면 중복 생략 정책을 유지합니다.

DB 저장 성공 후 캐시 완료 표시 실패는 성공한 이력을 실패로 바꾸지 않습니다. 다만 두 쓰기가 원자적이지 않아 다음 요청·동시 요청에서 중복 이력이 생길 수 있습니다. 완료 필드가 없는 기존 캐시는 저장을 재시도하지만 기존 `true`는 신뢰하므로 이전 코드가 잘못 표시한 완료 상태를 자동 복구하지 않습니다. 세부 호환 동작과 한계는 [직접 URL 이력 정책](backend/DIRECT_URL_HISTORY_POLICY.md)에 있습니다.

포함 URL은 **부모 QR 이력 한 건**에 링크별 공개 결과·실패 목록·완료 여부·연결 정책 버전·개수·성공 개수·최고 점수·제한 제외 플래그를 저장하며 `GET /scans`에서도 반환합니다. 과거 상세 미저장 기록은 `embedded_url_details_available=false`, 누락 목록·완료 여부는 `null`입니다. 새 무링크 기록의 `[]`와 완료 `true`와 구분하고, 과거 상세를 재분석해 만들어 넣지 않습니다. 저장 허용 필드와 JSON 변환 계약은 [포함 URL 이력 상세 정책](backend/EMBEDDED_URL_POLICY.md#포함-url-이력-상세-저장조회-계약)을 참고하세요.

### 스캔 기록 조회: `GET /scans`

`X-Admin-Key` 인증이 필요합니다. `limit`(기본 20, 최대 100)은 전체 페이지를 확인한 뒤 반환할 최신 저장 이력 수이며, `status`가 있으면 해당 상태의 최신 이력을 선택합니다. 성공 응답은 `items`와 조회 범위 `metadata`를 제공합니다. DB 비활성·조회 실패·상한 초과는 빈 목록이나 부분 최신 목록 대신 503입니다.

### 스캔 통계 조회: `GET /scans/summary`

이 API도 `X-Admin-Key` 인증이 필요합니다. `limit`(기본 200, 최대 500)은 **최근 N개 저장 이력**의 집계 범위입니다. `total`은 실제 집계 이력 수이며 전체 요청 횟수나 테이블 전체 건수가 아닙니다. 안전·주의·위험·미확인 개수는 같은 집합을 사용하고, `recent_items`는 그 집합의 최신 최대 10개입니다. VT 합계는 부모 이력 기준이며 자식 탐지 수를 임의로 더하지 않습니다. 직접 URL의 중복 생략 때문에 저장 이력 건수와 URL 캐시 `scan_count`는 다릅니다.

집계 범위·요청한 limit·반환/집계 건수는 `metadata`로 제공합니다. 시간순 Query에 적합한 인덱스는 저장소에서 확인되지 않아 **제한된 전체 Scan**을 사용합니다. 다음 페이지 키를 끝까지 처리한 뒤 `created_at`, 동일 시각이면 `scan_id` 내림차순으로 선택합니다. 조회 예산은 8초(응답 여유 1초), 최대 20페이지·평가 항목 4,000개·페이지당 최대 200개이며 절대 실행 시간 상한은 아닙니다.

상한 도달·중간 실패·반복 키 등 불완전 조회는 일반 안내와 공개 오류 코드의 503을 반환합니다. `SCAN_HISTORY_DISABLED`, `SCAN_HISTORY_READ_FAILED`, `SCAN_HISTORY_INCOMPLETE`를 정상 빈 테이블의 200·빈 목록/0건 통계와 구분합니다. 페이지 완료도 원자적 스냅샷을 보장하지 않습니다. 큰 테이블에는 검증된 시간순·상태별 인덱스 설계가 필요합니다. 상세 계약·응답 예시·조회 상한과 확장 한계는 [저장 이력 조회 정책](backend/SCAN_HISTORY_READ_POLICY.md)을 참고하세요.

## 요청 시간과 실패 처리

`/scan`, `/analyze-qr` 분석 함수 진입 시 `time.monotonic()` 기준 **12초 공유 예산**을 한 번 만들고 파싱·URL 분석·캐시·이력 저장이 함께 사용합니다. URL마다 예산을 다시 시작하지 않습니다. 외부 조회와 캐시는 저장·결과 정리를 위한 2초, 이력 저장은 응답 정리를 위한 1초를 남기며, 남은 시간에 맞춰 호출 배분을 줄입니다. 부족하면 추가 조회·제출·새 URL 분석을 시작하지 않습니다. 제출은 기존 활성화 조건에서만 수행하며 자동으로 켜지지 않습니다.

외부 평판만 미확인이면 완료한 로컬 분석을 반환합니다. URL 분석 자체가 미완료면 실패 목록·완료 여부로 구분하며 성공한 결과와 부모 점수를 보존합니다. 현재 규칙의 신선한 캐시는 재사용하지만 이전·누락 버전은 재계산하고 실패 결과를 새 버전으로 표시하지 않습니다.

앱 응답 대기는 **15초**이며 12초와의 차이는 통신·스케줄링 등을 고려한 여유입니다. **12초는 절대 실행 시간 상한이 아닙니다.** SDK 연결/읽기 타임아웃은 DNS·자격증명 조회·연속 수신·내부 처리 등을 강제 취소하지 않고, cold start·요청 대기·전송도 분석 예산 밖일 수 있습니다. 앱의 `Future.timeout`도 서버 처리를 취소하지 않습니다. 항상 15초 안에 응답한다는 운영 보장은 없으며, 실패 시 앱에서 일반 안내와 재스캔 흐름을 제공합니다. 상세 배분과 한계는 [분석 시간 정책](backend/ANALYSIS_TIME_POLICY.md)에 있습니다.

## 로컬 실행

Python 3.12와 Flutter SDK가 준비된 환경을 사용합니다. 아래 설치 명령은 환경 준비 안내이며 운영 연동을 자동으로 활성화하지 않습니다.

### 저장소와 백엔드 준비

PowerShell·Bash 공통 명령:

```text
git clone https://github.com/kimye72/Qshing_project.git
cd Qshing_project
```

이미 받은 저장소에서는 해당 루트에서 시작합니다. **Windows PowerShell**:

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
Copy-Item .env.example .env
```

**Bash(macOS/Linux)** — `python3`가 Python 3.12인지 먼저 확인합니다:

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
cp .env.example .env
```

이후 활성화한 환경에서 **PowerShell·Bash 공통**:

```text
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --reload
```

로컬 서버는 `http://127.0.0.1:8000`, Swagger 문서는 `http://127.0.0.1:8000/docs`입니다. `.env.example`은 VT 조회·404 제출·DB 저장·URL 캐시가 비활성입니다. 외부 연동이 필요할 때만 각 설정과 자격증명을 별도로 구성합니다. 관리자 API에는 서버의 `ADMIN_API_KEY` 설정과 `X-Admin-Key` 요청 헤더가 필요하며, 키 미구성·누락·불일치를 정상 조회로 처리하지 않습니다.

### Flutter 준비와 API_URL

프로젝트 루트에서 **PowerShell·Bash 공통**:

```text
cd qr_phishing_app
flutter doctor
flutter pub get
flutter devices
```

Android 실행에는 Android SDK와 기기 또는 에뮬레이터가 필요합니다. Flutter는 컴파일 환경값 **`API_URL`**에 `/analyze-qr` 엔드포인트를 받아야 하며, 누락하면 분석 요청을 보내지 않습니다. 아래 주소는 실제 API 주소가 아닌 자리표시자입니다.

**PowerShell·Bash 공통**:

```text
flutter run --dart-define=API_URL=https://YOUR_API_ENDPOINT/analyze-qr
flutter run -d chrome --dart-define=API_URL=https://YOUR_API_ENDPOINT/analyze-qr
```

명령행 대신 `api_config.example.json`을 `api_config.json`으로 복사하고 사용할 주소를 입력할 수 있습니다. **PowerShell**:

```powershell
Copy-Item api_config.example.json api_config.json
```

**Bash**:

```bash
cp api_config.example.json api_config.json
```

이후 **PowerShell·Bash 공통**:

```text
flutter run --dart-define-from-file=api_config.json
```

`api_config.json`은 Git에서 제외되는 로컬 설정입니다. Dart define은 배포된 앱에서 API 주소나 비밀을 보호하는 저장소가 아닙니다. Chrome 실행 예시가 플랫폼별 카메라·권한 동작의 검증을 뜻하지는 않습니다.

## 오프라인 테스트

활성화된 백엔드 테스트 환경에서 시작합니다. `backend` 디렉터리의 **PowerShell·Bash 공통** 준비 명령은 다음과 같습니다. `requirements-dev.txt`는 운영 의존성과 TestClient용 테스트 의존성을 포함하며 Lambda 빌드는 `requirements.txt`만 사용합니다.

```text
python -m pip install -r requirements-dev.txt
```

로컬 `.env`의 활성 설정을 덮어쓰기 위해 테스트 전에 외부 연동을 비활성화합니다. **Windows PowerShell**:

```powershell
$env:VIRUSTOTAL_ENABLED = 'false'
$env:VIRUSTOTAL_SUBMIT_IF_NOT_FOUND = 'false'
$env:DYNAMODB_ENABLED = 'false'
$env:URL_CACHE_ENABLED = 'false'
$env:AWS_EC2_METADATA_DISABLED = 'true'
```

**Bash**:

```bash
export VIRUSTOTAL_ENABLED=false VIRUSTOTAL_SUBMIT_IF_NOT_FOUND=false
export DYNAMODB_ENABLED=false URL_CACHE_ENABLED=false AWS_EC2_METADATA_DISABLED=true
```

위 설정을 적용한 **동일 셸**에서 공개 모듈을 명시적으로 실행합니다. **PowerShell·Bash 공통**:

```text
python -m unittest test_analyze_qr test_analysis_budget test_direct_url_history test_embedded_url_history test_scan_history_reads
```

테스트는 VT·DynamoDB를 mock하고 시간 예산은 가짜 시계로 확인합니다. 연구·study 디렉터리는 수집하지 않습니다. 실제 위험 URL 접속·VT 제출·운영 API 호출 결과를 검증한 것이 아닙니다.

Flutter 패키지를 준비한 `qr_phishing_app` 디렉터리에서 **PowerShell·Bash 공통**:

```text
flutter test --no-pub
flutter analyze --no-pub
```

모델·위젯·화면 상태 테스트는 저장소 fixture와 가짜 API 클라이언트·카메라 플랫폼을 사용합니다. 실제 카메라·권한·플랫폼 생명주기는 실기기 확인이 필요합니다. 테스트 개수나 성능·탐지율·운영 정상 여부는 이 안내로 보장하지 않습니다.

## 비공개 자료와 배포

`.gitignore`는 `.env`, 가상환경, `backend/package/`, `backend/lambda_deploy.zip`, Flutter 빌드·도구 산출물과 로컬 API 설정 등을 제외합니다. **`backend/research/`, `backend/study/`의 연구 코드·데이터·기대값·평판 스냅샷·결과 및 비공개 검토 자료는 현재 공개 작업 트리의 Git 추적 대상에서 제외**합니다. 이것이 과거 Git 이력에서도 제거되었다는 뜻은 아닙니다. 실제 키·AWS 자격증명은 소스나 실행 예시에 넣지 않습니다.

Lambda 패키지를 만들 때는 `backend`에서 **Windows PowerShell**로 실행합니다:

```powershell
.\build_lambda_package.ps1
```

스크립트는 Python 3.12·Linux x86_64 대상 의존성을 모으고 `package` 및 `lambda_deploy.zip`을 다시 생성합니다. 패키지 생성이 실제 Lambda 배포나 운영 확인을 수행하는 것은 아닙니다.

## 향후 개선과 남은 한계

Punycode 호스트 탐지와 단축 URL 규칙은 이미 구현되어 있습니다. 단축 주소의 최종 목적지 확인이나 **리디렉션 추적은 구현하지 않았습니다**. 향후에는 리디렉션 분석, 도메인 유사성·브랜드 목록 개선, 오탐·미탐 평가, 큰 이력 테이블의 시간순 인덱스, 저장 멱등성·취소 가능한 시간 제한을 검토할 수 있습니다. 실제 소유권·TLS 지원·안전성을 보장하거나 검증되지 않은 탐지율·응답 성능을 주장하지 않습니다.
