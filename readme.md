# Qshing Project

QR 코드를 스캔한 뒤 즉시 실행하지 않고, QR 코드에 포함된 내용을 먼저 분석하여 피싱 위험도와 판단 근거를 제공하는 **큐싱(QR Phishing) 예방 애플리케이션**입니다.

URL뿐만 아니라 전화번호, SMS, 이메일, Wi-Fi, 일반 텍스트 등 다양한 형태의 QR 콘텐츠를 분석할 수 있도록 구현하였습니다.

---

## 주요 기능

- QR 코드 스캔 및 원본 데이터 추출
- QR 콘텐츠 자동 실행 방지
- URL / 비URL QR 유형 분류
- 규칙 기반 위험도 분석
- VirusTotal API를 활용한 URL 평판 조회
- 위험 점수 및 `safe / warning / danger` 상태 제공
- 위험 판단 사유 제공
- DynamoDB를 이용한 스캔 결과 저장
- Flutter 앱에서 분석 결과 시각화

---

## 시스템 구조

```text
QR Code
   ↓
Flutter App
   ↓
FastAPI Backend
   ↓
QR Content Analysis
   ├─ URL Analysis
   ├─ Non-URL Analysis
   └─ VirusTotal
   ↓
Risk Score / Status / Reasons
   ↓
Flutter Result Screen
   ↓
DynamoDB
```

---

## 프로젝트 구조

```text
Qshing_project/
├─ backend/
│  ├─ app/
│  │  ├─ main.py
│  │  ├─ schemas.py
│  │  └─ services/
│  │     ├─ qr_analyzer.py
│  │     └─ ...
│  │
│  ├─ requirements.txt
│  ├─ build_lambda_package.ps1
│  └─ .env.example
│
├─ qr_phishing_app/
│  ├─ android/
│  ├─ ios/
│  ├─ lib/
│  │  └─ main.dart
│  ├─ web/
│  ├─ windows/
│  ├─ linux/
│  ├─ macos/
│  ├─ pubspec.yaml
│  └─ pubspec.lock
│
├─ .gitignore
└─ README.md
```

---

## 사용 기술

### Backend

- Python
- FastAPI
- Pydantic
- Mangum
- AWS Lambda
- Amazon API Gateway
- Amazon DynamoDB
- VirusTotal API

### Application

- Flutter
- Dart
- `mobile_scanner`
- `http`

---

# 실행 방법

## 1. Repository Clone

```bash
git clone https://github.com/kimye72/Qshing_project.git
cd Qshing_project
```

---

# Backend

## 2. Python 가상환경 생성

### Windows PowerShell

```powershell
cd backend

python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### macOS / Linux

```bash
cd backend

python3 -m venv .venv
source .venv/bin/activate
```

---

## 3. Python 패키지 설치

```bash
pip install -r requirements.txt
```

---

## 4. 환경 변수 설정

`.env.example` 파일을 복사하여 `.env` 파일을 생성합니다.

### Windows

```powershell
Copy-Item .env.example .env
```

### macOS / Linux

```bash
cp .env.example .env
```

예시:

```env
VIRUSTOTAL_ENABLED=false
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
VIRUSTOTAL_SUBMIT_IF_NOT_FOUND=false
VIRUSTOTAL_TIMEOUT_SECONDS=10

DYNAMODB_ENABLED=false
DYNAMODB_TABLE_NAME=qr_scan_results
AWS_REGION=ap-northeast-2
```

VirusTotal 또는 DynamoDB를 사용하지 않는 경우 해당 기능을 `false`로 설정하여 실행할 수 있습니다.

> 실제 API Key, AWS Credential 등의 민감정보는 Git 저장소에 업로드하지 마세요.

---

## 5. FastAPI 서버 실행

```bash
uvicorn app.main:app --reload
```

정상적으로 실행되면 다음 주소에서 API를 확인할 수 있습니다.

```text
http://127.0.0.1:8000
```

Swagger API 문서:

```text
http://127.0.0.1:8000/docs
```

---

## 주요 API

### QR 분석

```http
POST /analyze-qr
```

Request:

```json
{
  "content": "QR code raw content"
}
```

분석 결과에는 QR 유형, 위험 점수, 위험 상태 및 판단 사유 등이 포함됩니다.

### URL 분석

```http
POST /scan
```

### 스캔 기록 조회

```http
GET /scans
```

### 스캔 통계 조회

```http
GET /scans/summary
```

---

# Flutter Application

## 6. Flutter 환경 확인

Flutter SDK가 설치되어 있어야 합니다.

```bash
flutter doctor
```

Android 앱을 실행할 경우 Android Studio 및 Android SDK도 필요합니다.

---

## 7. Flutter 패키지 설치

프로젝트 루트에서:

```bash
cd qr_phishing_app
flutter pub get
```

---

## 8. 실행 가능한 Device 확인

```bash
flutter devices
```

---

## 9. Flutter 앱 실행

Backend API 주소를 직접 주입하여 연결된 Android 기기 또는 Emulator에서 실행합니다.

```bash
flutter run --dart-define=API_URL=https://YOUR_API_ENDPOINT/analyze-qr
```

Chrome에서 실행하려면:

```bash
flutter run -d chrome --dart-define=API_URL=https://YOUR_API_ENDPOINT/analyze-qr
```

---

## Backend API 주소 설정

Flutter 앱은 `API_URL` 컴파일 환경값으로 Backend API 주소를 받습니다. `API_URL`을 지정하지 않으면 분석 요청을 보내지 않습니다.

명령행 대신 설정 파일을 사용하려면 `api_config.example.json`을 `api_config.json`으로 복사한 뒤 실제 API 주소를 입력합니다.

```bash
flutter run --dart-define-from-file=api_config.json
```

`api_config.json`은 로컬 설정 파일이며 Git에서 제외됩니다. Dart define은 공개 소스의 하드코딩을 제거하기 위한 설정 수단이며, 배포된 앱에서 API 주소를 비밀로 보호하는 저장소는 아닙니다.

---

# QR 분석 방식

QR 코드를 스캔하면 내용을 즉시 실행하지 않고 먼저 Backend로 전달하여 분석합니다.

## URL QR

다음과 같은 특징을 기반으로 위험도를 판단합니다.

- HTTP 사용 여부
- IP 주소 포함 여부
- URL 길이
- 의심 키워드
- 단축 URL 여부
- 특수한 URL 구조
- VirusTotal 탐지 결과

## 비URL QR

URL이 아닌 QR에 대해서도 콘텐츠의 형식을 분석합니다.

예시:

- 일반 텍스트
- 전화번호
- SMS
- 이메일
- Wi-Fi 정보
- URL이 포함된 텍스트
- 위험한 Scheme
- 개인정보 및 인증 관련 키워드

---

# 위험도 분류

분석 결과는 위험 점수에 따라 세 단계로 분류합니다.

| 위험 점수 | 상태      | 의미        |
| --------: | --------- | ----------- |
|    0 ~ 29 | `safe`    | 비교적 안전 |
|   30 ~ 69 | `warning` | 주의 필요   |
|  70 ~ 100 | `danger`  | 높은 위험   |

위험 점수는 절대적인 안전 여부를 보장하는 값이 아니라, QR 콘텐츠에서 발견된 여러 위험 요소를 기반으로 산정한 참고 지표입니다.

---

# Security

다음 파일 및 정보는 GitHub에 포함하지 않습니다.

```text
.env
.venv/
backend/package/
backend/lambda_deploy.zip
qr_phishing_app/.dart_tool/
qr_phishing_app/build/
```

또한 다음과 같은 민감정보를 소스코드에 직접 작성하지 않습니다.

- VirusTotal API Key
- AWS Access Key
- AWS Secret Access Key
- AWS Session Token
- 기타 인증 정보

민감정보는 환경 변수 또는 AWS 서비스의 환경 변수 설정을 통해 관리합니다.

---

# AWS Lambda 배포

Backend는 FastAPI와 Mangum을 사용하여 AWS Lambda에서 실행할 수 있도록 구성되어 있습니다.

Lambda 배포 패키지를 생성할 경우 `backend` 디렉터리에서 다음 스크립트를 사용할 수 있습니다.

```powershell
.\build_lambda_package.ps1
```

생성되는 `lambda_deploy.zip` 파일은 빌드 산출물이므로 Git 저장소에는 포함하지 않습니다.

---

# 향후 개선 방향

현재 시스템을 기반으로 다음 기능을 추가적으로 고도화할 예정입니다.

- URL 구조 분석 강화
- 단축 URL 및 Redirect 분석
- 유사 도메인 및 Punycode 탐지
- 비URL QR 콘텐츠 분석 강화
- 위험 판단 근거 세분화
- QR 실행 전 사용자 확인 절차 개선
- 정상/피싱 QR 데이터 기반 탐지 성능 평가
- 오탐 및 미탐 사례 분석

---

## 목적

본 프로젝트는 QR 코드를 단순히 읽고 실행하는 기존 방식에서 벗어나, **QR 콘텐츠를 실행하기 전에 위험 요소를 먼저 확인할 수 있도록 하는 예방 중심의 보안 시스템 구축**을 목표로 합니다.
