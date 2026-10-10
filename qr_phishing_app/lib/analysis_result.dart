import 'dart:convert';

enum ReputationAvailability { available, unavailable, unknown }

enum ReputationLookupStatus {
  available,
  cached,
  lookupFailed,
  timeout,
  budgetExhausted,
  rateLimited,
  reportMissing,
  submitted,
  disabled,
  unknown,
}

enum ReputationSource {
  requestedReport,
  storedReport,
  historicalReport,
  unknown,
}

// Preserve missing fields as unknown; never turn a missing VT count into zero.
class UrlReputation {
  final bool? available;
  final int? malicious;
  final int? suspicious;
  final ReputationLookupStatus lookupStatus;
  final ReputationSource source;
  final bool historicalReputationUsed;

  const UrlReputation({
    this.available,
    this.malicious,
    this.suspicious,
    this.lookupStatus = ReputationLookupStatus.unknown,
    this.source = ReputationSource.unknown,
    this.historicalReputationUsed = false,
  });

  factory UrlReputation.fromJson(Map<String, dynamic> json) {
    final lookupStatus = switch (json['vt_lookup_status']) {
      'available' => ReputationLookupStatus.available,
      'cached' => ReputationLookupStatus.cached,
      'lookup_failed' => ReputationLookupStatus.lookupFailed,
      'timeout' => ReputationLookupStatus.timeout,
      'budget_exhausted' => ReputationLookupStatus.budgetExhausted,
      'rate_limited' => ReputationLookupStatus.rateLimited,
      'report_missing' => ReputationLookupStatus.reportMissing,
      'submitted' => ReputationLookupStatus.submitted,
      'disabled' => ReputationLookupStatus.disabled,
      _ => ReputationLookupStatus.unknown,
    };
    final historical =
        _object(json['analysis_flags'])?['historical_reputation_used'] == true;
    final available = _optionalBool(json['vt_available']);
    final source = switch (json['vt_source']) {
      'url_report' => ReputationSource.requestedReport,
      'cached_report' =>
        historical ||
                (available == false &&
                    lookupStatus != ReputationLookupStatus.unknown &&
                    lookupStatus != ReputationLookupStatus.cached &&
                    lookupStatus != ReputationLookupStatus.available)
            ? ReputationSource.historicalReport
            : ReputationSource.storedReport,
      // Compatibility: only affirmative historical/cache evidence may infer
      // a missing source. Revalidation reasons (including cache_miss) never do.
      null =>
        historical
            ? ReputationSource.historicalReport
            : available == true &&
                  (lookupStatus == ReputationLookupStatus.cached ||
                      (json['cache_hit'] == true &&
                          json['cache_revalidated'] != true &&
                          lookupStatus == ReputationLookupStatus.unknown))
            ? ReputationSource.storedReport
            : ReputationSource.unknown,
      _ => ReputationSource.unknown,
    };
    // Submission acceptance and failed lookups cannot become completed reports,
    // even if an older response incorrectly marks them available.
    final failedLookup = switch (lookupStatus) {
      ReputationLookupStatus.available ||
      ReputationLookupStatus.cached ||
      ReputationLookupStatus.unknown => false,
      _ => true,
    };
    return UrlReputation(
      available: failedLookup || json['vt_source'] == 'submitted_analysis'
          ? false
          : available,
      malicious: _optionalCount(json['vt_malicious']),
      suspicious: _optionalCount(json['vt_suspicious']),
      lookupStatus: lookupStatus,
      source: source,
      historicalReputationUsed:
          historical || source == ReputationSource.historicalReport,
    );
  }

  ReputationAvailability get availability => switch (available) {
    true => ReputationAvailability.available,
    false => ReputationAvailability.unavailable,
    null => ReputationAvailability.unknown,
  };
}

class EmbeddedUrlTarget {
  final String originalUrl;
  final List<String> originalCandidates;
  final String analysisUrl;
  final bool assumedHttps;

  EmbeddedUrlTarget.fromJson(Map<String, dynamic> json)
    : originalUrl = _optionalString(json['original_url']) ?? '',
      originalCandidates = _strings(json['original_candidates']),
      analysisUrl =
          _optionalString(json['analysis_url']) ??
          _optionalString(json['url']) ??
          '',
      assumedHttps = json['assumed_https'] == true;
}

class EmbeddedUrlAnalysis extends EmbeddedUrlTarget {
  final num? score;
  final String? status;
  final List<String> reasons;
  final UrlReputation reputation;

  EmbeddedUrlAnalysis.fromJson(super.json)
    : score =
          _optionalScore(json['final_score']) ??
          _optionalScore(json['risk_score']),
      status = _optionalStatus(json['status']),
      reasons = _reasons(json['reasons']),
      reputation = UrlReputation.fromJson(json),
      super.fromJson();
}

class EmbeddedUrlFailure extends EmbeddedUrlTarget {
  // Only the public code is retained. Raw error/exception fields are ignored.
  final String? errorCode;

  EmbeddedUrlFailure.fromJson(super.json)
    : errorCode = _optionalString(json['error_code']),
      super.fromJson();
}

class AnalysisResult {
  final String qrType;
  final String preview;
  final num riskScore;
  final String status;
  final String message;
  final List<String> reasons;
  final String? url;
  final bool containsUrl;
  final UrlReputation reputation;
  final List<EmbeddedUrlAnalysis> embeddedUrls;
  final List<EmbeddedUrlFailure> embeddedFailures;
  final int? embeddedUrlCount;
  final int? analyzedEmbeddedUrlCount;
  final bool? embeddedAnalysisComplete;
  final int? skippedEmbeddedUrlCount;

  AnalysisResult._(Map<String, dynamic> json)
    : qrType = json['qr_type'] as String,
      preview = json['raw_content_preview'] as String,
      riskScore = json['risk_score'] as num,
      status = json['status'] as String,
      message = json['message'] as String,
      reasons = _reasons(json['reasons']),
      url = _optionalString(json['url']),
      containsUrl = json['contains_url'] == true,
      reputation = UrlReputation.fromJson(json),
      embeddedUrls = _objects(
        json['embedded_url_results'],
      ).map(EmbeddedUrlAnalysis.fromJson).toList(growable: false),
      embeddedFailures = _objects(
        json['embedded_url_failures'],
      ).map(EmbeddedUrlFailure.fromJson).toList(growable: false),
      embeddedUrlCount = _optionalCount(json['embedded_url_count']),
      analyzedEmbeddedUrlCount = _optionalCount(
        json['analyzed_embedded_url_count'],
      ),
      embeddedAnalysisComplete = _optionalBool(
        json['embedded_url_analysis_complete'],
      ),
      skippedEmbeddedUrlCount = _optionalCount(
        _object(json['analysis_flags'])?['embedded_url_skipped_count'],
      );

  factory AnalysisResult.fromJson(Map<String, dynamic> json) {
    // Keep the original response contract; new metadata is optional for older APIs.
    if (json['qr_type'] is! String ||
        json['raw_content_preview'] is! String ||
        _optionalScore(json['risk_score']) == null ||
        _optionalStatus(json['status']) == null ||
        json['message'] is! String ||
        json['reasons'] is! List) {
      throw const FormatException('Analysis response fields are invalid.');
    }
    return AnalysisResult._(json);
  }

  factory AnalysisResult.fromBodyBytes(List<int> bytes) {
    final json = _object(jsonDecode(utf8.decode(bytes)));
    if (json == null) {
      throw const FormatException('Analysis response is not an object.');
    }
    return AnalysisResult.fromJson(json);
  }

  bool get hasEmbeddedTargets =>
      embeddedUrls.isNotEmpty ||
      embeddedFailures.isNotEmpty ||
      (embeddedUrlCount ?? 0) > 0;

  // SMS/mailto extraction fields can also contain recipients/subjects. Only
  // actual body-analysis metadata identifies their analyzed links.
  bool get showParentReputation =>
      qrType == 'url' ||
      (qrType == 'text_with_url' &&
          !hasEmbeddedTargets &&
          (containsUrl || url != null));

  bool get isIncomplete =>
      embeddedAnalysisComplete == false ||
      embeddedFailures.isNotEmpty ||
      (skippedEmbeddedUrlCount ?? 0) > 0;

  String get displayMessage => status == 'safe'
      ? '현재 확인한 정보에서 위험 신호가 적게 나타났습니다. 실제 안전성을 보장하지 않습니다.'
      : message;
}

String riskStatusLabel(String? status) => switch (status) {
  'safe' => '낮은 위험',
  'warning' => '주의',
  'danger' => '위험',
  _ => '판정 확인 불가',
};

bool? _optionalBool(dynamic value) => value is bool ? value : null;
String? _optionalString(dynamic value) => value is String ? value : null;
num? _optionalScore(dynamic value) =>
    value is num && value.isFinite ? value : null;
int? _optionalCount(dynamic value) => value is int && value >= 0 ? value : null;
String? _optionalStatus(dynamic value) =>
    const {'safe', 'warning', 'danger'}.contains(value)
    ? value as String
    : null;
List<String> _strings(dynamic value) => value is List
    ? value.whereType<String>().toList(growable: false)
    : const [];
Map<String, dynamic>? _object(dynamic value) =>
    value is Map<String, dynamic> ? value : null;
List<Map<String, dynamic>> _objects(dynamic value) => value is List
    ? value.whereType<Map<String, dynamic>>().toList(growable: false)
    : const [];

List<String> _reasons(dynamic value) => _strings(value)
    .map((reason) {
      // Older backends put VT configuration/exception details in a reason string.
      if (reason.startsWith('VirusTotal 조회 결과 미사용:')) {
        return '외부 평판 정보를 사용할 수 없어 해당 정보는 점수에 반영하지 않았습니다.';
      }
      return reason;
    })
    .toList(growable: false);
