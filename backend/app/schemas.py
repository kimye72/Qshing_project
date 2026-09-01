from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, HttpUrl, TypeAdapter, field_validator


_HTTP_URL_ADAPTER = TypeAdapter(HttpUrl)


class EmbeddedUrlResult(BaseModel):
    url: str = Field(..., description="분석한 포함 URL")
    domain: Optional[str] = Field(default=None, description="포함 URL 도메인")
    local_score: int = Field(..., description="포함 URL의 로컬 규칙 점수")
    vt_score_delta: int = Field(..., description="포함 URL의 VirusTotal 가산 점수")
    final_score: int = Field(..., description="포함 URL의 최종 위험 점수")
    risk_score: int = Field(..., description="포함 URL의 최종 위험 점수 호환 필드")
    status: Literal["safe", "warning", "danger"] = Field(..., description="포함 URL 상태")
    reasons: List[str] = Field(default_factory=list, description="포함 URL 판단 사유")
    analysis_flags: Optional[Dict[str, Any]] = Field(default=None, description="포함 URL 분석 플래그")
    ruleset_version: str = Field(..., description="포함 URL 분석 규칙 버전")
    vt_available: bool = Field(default=False, description="VT 리포트 사용 가능 여부")
    vt_source: Optional[str] = Field(default=None, description="VT 결과 출처")
    vt_malicious: int = Field(default=0, description="VT 악성 탐지 수")
    vt_suspicious: int = Field(default=0, description="VT 의심 탐지 수")
    vt_harmless: int = Field(default=0, description="VT 무해 탐지 수")
    vt_undetected: int = Field(default=0, description="VT 미탐지 수")
    cache_hit: bool = Field(default=False, description="fresh URL 캐시 사용 여부")
    cache_age_seconds: Optional[int] = Field(default=None, ge=0, description="캐시 경과 시간")
    cache_revalidated: bool = Field(default=False, description="요청 중 재검증 여부")
    revalidation_reason: Optional[Literal["cache_miss", "ruleset_changed", "stale_cache"]] = Field(
        default=None,
        description="캐시 미사용 또는 재검증 사유",
    )


class ScanRequest(BaseModel):
    url: str = Field(
        ...,
        description="분석할 URL",
        json_schema_extra={"format": "uri"},
    )

    @field_validator("url")
    @classmethod
    def preserve_validated_url(cls, value: str) -> str:
        analysis_url = value.strip()
        _HTTP_URL_ADAPTER.validate_python(analysis_url)
        return analysis_url


class ScanResponse(BaseModel):
    url: str = Field(..., description="분석한 URL")
    domain: Optional[str] = Field(default=None, description="URL에서 추출한 도메인")
    decoded_url: Optional[str] = Field(default=None, description="URL 디코딩 후 값이 달라진 경우의 디코딩 URL")
    qr_type: str = Field(default="url", description="분석 콘텐츠 유형")
    contains_url: bool = Field(default=True, description="URL 포함 여부")
    extracted_urls: List[str] = Field(default_factory=list, description="분석 대상 URL 목록")
    local_score: int = Field(..., description="VirusTotal 적용 전 로컬 규칙 점수")
    vt_score_delta: int = Field(..., description="VirusTotal 정책에 따른 가산 점수")
    final_score: int = Field(..., description="최종 위험 점수")
    risk_score: int = Field(..., description="위험 점수 (0~100)")
    ruleset_version: str = Field(..., description="탐지 규칙 버전")
    status: Literal["safe", "warning", "danger"] = Field(..., description="분석 결과 상태")
    message: str = Field(..., description="사용자에게 보여줄 결과 메시지")
    reasons: List[str] = Field(..., description="위험 판단 사유 목록")
    analysis_flags: Optional[Dict[str, Any]] = Field(default=None, description="탐지 휴리스틱 플래그")

    #VirusTotal에서 받는 값
    vt_available: Optional[bool] = Field(default=False, description="리포트 사용 가능 여부")
    vt_source: Optional[str] = Field(default=None, description="결과 출처")
    vt_malicious: Optional[int] = Field(default=0, description="악성 탐지 수")
    vt_suspicious: Optional[int] = Field(default=0, description="의심 탐지 수")
    vt_harmless: Optional[int] = Field(default=0, description="무해 탐지 수")
    vt_undetected: Optional[int] = Field(default=0, description="미탐지 수")
    raw_result: Optional[Dict[str, Any]] = Field(default=None, description="원본 분석 결과 데이터")

    cache_hit: bool = Field(default=False, description="fresh URL 캐시 결과 사용 여부")
    cache_age_seconds: Optional[int] = Field(default=None, ge=0, description="캐시 검사 시각 기준 경과 시간")
    cache_revalidated: bool = Field(default=False, description="요청 중 캐시 재검증 완료 여부")
    revalidation_reason: Optional[Literal["cache_miss", "ruleset_changed", "stale_cache"]] = Field(
        default=None,
        description="캐시 미사용 또는 재검증 사유",
    )
    
    scan_id: Optional[str] = Field(default=None, description="DB 저장용 고유 ID")
    created_at: Optional[str] = Field(default=None, description="분석 결과 생성 시간")
    date: Optional[str] = Field(default=None, description="대시보드 날짜 필터용 날짜")
    db_saved: Optional[bool] = Field(default=False, description="DB 저장 성공 여부")
    db_error: Optional[str] = Field(default=None, description="DB 저장 실패 시 오류 메시지")
    history_saved: Optional[bool] = Field(default=None, description="URL 분석 이력 저장 성공 여부")
    history_event_type: Optional[str] = Field(default=None, description="URL 분석 이력 이벤트 유형")
    history_skip_reason: Optional[str] = Field(default=None, description="URL 분석 이력을 저장하지 않은 사유")

class QRAnalyzeRequest(BaseModel):
    content: str = Field(
        ...,
        min_length=1,
        max_length=4096,
        description="QR 코드에서 추출한 원본 내용"
    )

class QRAnalyzeResponse(BaseModel):
    qr_type: str = Field(..., description="QR 유형: url / text / phone_text / sms / email / wifi 등")
    raw_content_preview: str = Field(..., description="마스킹 처리된 QR 내용 미리보기")
    contains_url: bool = Field(..., description="QR 내용에 URL이 포함되어 있는지 여부")
    extracted_urls: List[str] = Field(default_factory=list, description="QR 내용에서 추출된 URL 목록")
    contains_url_candidate: bool = Field(
        default=False,
        description="프로토콜이 없는 URL 후보 포함 여부",
    )
    extracted_url_candidates: List[str] = Field(
        default_factory=list,
        description="프로토콜이 없는 URL 후보 목록",
    )
    candidate_url_count: int = Field(
        default=0,
        description="중복 제거된 프로토콜 없는 URL 후보 수",
    )
    text_score: Optional[int] = Field(default=None, description="텍스트 자체 위험 점수")
    embedded_url_count: int = Field(default=0, description="중복 제거된 포함 URL 수")
    analyzed_embedded_url_count: int = Field(default=0, description="실제 분석에 성공한 포함 URL 수")
    embedded_url_max_score: Optional[int] = Field(default=None, description="포함 URL 중 최고 최종 점수")
    embedded_url_results: List[EmbeddedUrlResult] = Field(
        default_factory=list,
        description="분석된 포함 URL별 결과",
    )

    url: Optional[str] = Field(default=None, description="분석 대상 URL")
    domain: Optional[str] = Field(default=None, description="도메인")
    decoded_url: Optional[str] = Field(default=None, description="URL 디코딩 후 값")

    local_score: int = Field(..., description="VirusTotal 적용 전 로컬 규칙 점수")
    vt_score_delta: int = Field(..., description="VirusTotal 정책에 따른 가산 점수")
    final_score: int = Field(..., description="최종 위험 점수")
    risk_score: int = Field(..., description="위험 점수")
    ruleset_version: str = Field(..., description="탐지 규칙 버전")
    status: Literal["safe", "warning", "danger"] = Field(..., description="분석 결과 상태")
    message: str = Field(..., description="사용자 안내 메시지")
    reasons: List[str] = Field(..., description="위험 판단 사유")

    analysis_flags: Optional[Dict[str, Any]] = Field(default=None, description="분석 플래그")
    raw_result: Optional[Dict[str, Any]] = Field(default=None, description="원본 분석 결과")

    vt_available: Optional[bool] = Field(default=False, description="VT 리포트 사용 가능 여부")
    vt_source: Optional[str] = Field(default=None, description="VT 결과 출처")
    vt_malicious: Optional[int] = Field(default=0, description="VT 악성 탐지 수")
    vt_suspicious: Optional[int] = Field(default=0, description="VT 의심 탐지 수")
    vt_harmless: Optional[int] = Field(default=0, description="VT 무해 탐지 수")
    vt_undetected: Optional[int] = Field(default=0, description="VT 미탐지 수")

    cache_hit: bool = Field(default=False, description="fresh URL 캐시 결과 사용 여부")
    cache_age_seconds: Optional[int] = Field(default=None, ge=0, description="캐시 검사 시각 기준 경과 시간")
    cache_revalidated: bool = Field(default=False, description="요청 중 캐시 재검증 완료 여부")
    revalidation_reason: Optional[Literal["cache_miss", "ruleset_changed", "stale_cache"]] = Field(
        default=None,
        description="캐시 미사용 또는 재검증 사유",
    )

    scan_id: Optional[str] = Field(default=None)
    created_at: Optional[str] = Field(default=None)
    date: Optional[str] = Field(default=None)
    db_saved: Optional[bool] = Field(default=False)
    db_error: Optional[str] = Field(default=None)
    history_saved: Optional[bool] = Field(default=None, description="URL 분석 이력 저장 성공 여부")
    history_event_type: Optional[str] = Field(default=None, description="URL 분석 이력 이벤트 유형")
    history_skip_reason: Optional[str] = Field(default=None, description="URL 분석 이력을 저장하지 않은 사유")
