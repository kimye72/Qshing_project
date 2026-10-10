import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:qr_phishing_app/analysis_result.dart';

import 'fixtures/analysis_responses.dart';

void main() {
  test('explicit unknown source does not hide affirmative historical use', () {
    final json = historicalReport()..['vt_source'] = 'future_source';
    final reputation = UrlReputation.fromJson(json);
    expect(reputation.source, ReputationSource.unknown);
    expect(reputation.historicalReputationUsed, isTrue);
    expect(reputation.lookupStatus, ReputationLookupStatus.timeout);
    expect(reputation.malicious, 3);
  });

  test(
    'cache miss and successful revalidation retrieve a report this request',
    () {
      for (final revalidated in [false, true]) {
        final reputation = UrlReputation.fromJson(
          requestedReport(revalidated: revalidated),
        );
        expect(reputation.lookupStatus, ReputationLookupStatus.available);
        expect(reputation.source, ReputationSource.requestedReport);
        expect(reputation.availability, ReputationAvailability.available);
      }
    },
  );

  test(
    'explicit source wins over cache metadata and unknown sources stay unknown',
    () {
      final json = requestedReport()..['cache_hit'] = true;
      expect(
        UrlReputation.fromJson(json).source,
        ReputationSource.requestedReport,
      );
      json['vt_source'] = 'future_source';
      expect(UrlReputation.fromJson(json).source, ReputationSource.unknown);
      json['vt_source'] = 'cached_report';
      expect(
        UrlReputation.fromJson(json).source,
        ReputationSource.storedReport,
      );
    },
  );

  test(
    'failed revalidation retains historical counts and separate lookup state',
    () {
      for (final status in [
        'timeout',
        'rate_limited',
        'lookup_failed',
        'disabled',
      ]) {
        final reputation = UrlReputation.fromJson(
          historicalReport(status: status),
        );
        expect(reputation.source, ReputationSource.historicalReport);
        expect(reputation.availability, ReputationAvailability.unavailable);
        expect(reputation.malicious, 3);
        expect(reputation.suspicious, 2);
      }
      final json = historicalReport()..remove('analysis_flags');
      expect(
        UrlReputation.fromJson(json).source,
        ReputationSource.historicalReport,
      );
    },
  );

  test(
    'legacy fallback needs affirmative evidence, never a revalidation reason',
    () {
      final miss = requestedReport()..remove('vt_source');
      expect(UrlReputation.fromJson(miss).source, ReputationSource.unknown);
      miss['revalidation_reason'] = 'stale_cache';
      expect(UrlReputation.fromJson(miss).source, ReputationSource.unknown);
      final hit = cachedReport()..remove('vt_source');
      expect(UrlReputation.fromJson(hit).source, ReputationSource.storedReport);
      hit.remove('vt_lookup_status');
      expect(UrlReputation.fromJson(hit).source, ReputationSource.storedReport);
      hit['cache_revalidated'] = true;
      expect(UrlReputation.fromJson(hit).source, ReputationSource.unknown);
      final historical = historicalReport()..remove('vt_source');
      expect(
        UrlReputation.fromJson(historical).source,
        ReputationSource.historicalReport,
      );
    },
  );

  test('actual lookup states are typed independently of report source', () {
    const states = {
      'lookup_failed': ReputationLookupStatus.lookupFailed,
      'timeout': ReputationLookupStatus.timeout,
      'budget_exhausted': ReputationLookupStatus.budgetExhausted,
      'rate_limited': ReputationLookupStatus.rateLimited,
      'report_missing': ReputationLookupStatus.reportMissing,
      'submitted': ReputationLookupStatus.submitted,
      'disabled': ReputationLookupStatus.disabled,
      'future_state': ReputationLookupStatus.unknown,
    };
    for (final entry in states.entries) {
      final reputation = UrlReputation.fromJson({
        'vt_lookup_status': entry.key,
        'vt_available': false,
      });
      expect(reputation.lookupStatus, entry.value);
      expect(reputation.source, ReputationSource.unknown);
      expect(reputation.malicious, isNull);
    }
  });

  test('legacy submission acceptance never becomes a completed reputation', () {
    for (final json in [
      {'vt_available': true, 'vt_source': 'submitted_analysis'},
      {'vt_available': true, 'vt_lookup_status': 'submitted'},
    ]) {
      final reputation = UrlReputation.fromJson(json);
      expect(reputation.availability, ReputationAvailability.unavailable);
      expect(reputation.source, ReputationSource.unknown);
    }
  });

  test(
    'missing and invalid metadata/counts never create a successful report',
    () {
      for (final json in [
        <String, dynamic>{},
        {
          'vt_source': 1,
          'vt_lookup_status': true,
          'vt_malicious': '0',
          'vt_suspicious': -1,
        },
      ]) {
        final reputation = UrlReputation.fromJson(json);
        expect(reputation.availability, ReputationAvailability.unknown);
        expect(reputation.source, ReputationSource.unknown);
        expect(reputation.lookupStatus, ReputationLookupStatus.unknown);
        expect(reputation.malicious, isNull);
        expect(reputation.suspicious, isNull);
      }
    },
  );

  test(
    'parent and distinct children retain independent sources and counts',
    () {
      final result = AnalysisResult.fromJson(
        withEmbeddedUrls([
          embeddedResponse()..addAll(requestedReport()),
          embeddedResponse()..addAll(cachedReport()),
          embeddedResponse()..addAll(historicalReport()),
        ])..addAll(requestedReport()),
      );
      expect(result.embeddedUrls.map((url) => url.reputation.source), [
        ReputationSource.requestedReport,
        ReputationSource.storedReport,
        ReputationSource.historicalReport,
      ]);
      expect(result.reputation.malicious, 0);
      expect(result.embeddedUrls.last.reputation.malicious, 3);
      expect(result.showParentReputation, isFalse);
    },
  );

  test('UTF-8 JSON preserves backend score/status and nested URL metadata', () {
    final json = withEmbeddedUrls([
      {
        ...embeddedResponse(url: 'https://example.invalid/Path?Token=AbC'),
        'original_url': 'Example.invalid/Path?Token=AbC',
        'original_candidates': ['Example.invalid/Path?Token=AbC'],
        'assumed_https': true,
      },
    ])..addAll({'risk_score': 85, 'status': 'danger'});
    final result = AnalysisResult.fromBodyBytes(utf8.encode(jsonEncode(json)));
    expect(result.riskScore, 85);
    expect(result.status, 'danger');
    final child = result.embeddedUrls.single;
    expect(child.score, 10);
    expect(child.analysisUrl, 'https://example.invalid/Path?Token=AbC');
    expect(child.originalCandidates, ['Example.invalid/Path?Token=AbC']);
    expect(child.assumedHttps, isTrue);
  });

  test('available, unavailable and missing reputation remain distinct', () {
    final json = analysisResponse();
    expect(
      AnalysisResult.fromJson(json).reputation.availability,
      ReputationAvailability.unavailable,
    );
    json['vt_available'] = true;
    expect(
      AnalysisResult.fromJson(json).reputation.availability,
      ReputationAvailability.available,
    );
    json.remove('vt_available');
    expect(
      AnalysisResult.fromJson(json).reputation.availability,
      ReputationAvailability.unknown,
    );
    for (final invalid in [null, 'true', 1]) {
      json['vt_available'] = invalid;
      expect(
        AnalysisResult.fromJson(json).reputation.availability,
        ReputationAvailability.unknown,
      );
    }
  });

  test('missing VT counts are not interpreted as zero detections', () {
    final json = analysisResponse()..['vt_available'] = true;
    json.remove('vt_malicious');
    json.remove('vt_suspicious');
    final reputation = AnalysisResult.fromJson(json).reputation;
    expect(reputation.malicious, isNull);
    expect(reputation.suspicious, isNull);
  });

  test('child reputation does not inherit parent or sibling VT fields', () {
    final missing = embeddedResponse()..remove('vt_available');
    final result = AnalysisResult.fromJson(
      withEmbeddedUrls([
        embeddedResponse(available: true),
        embeddedResponse(),
        missing,
      ])..['vt_available'] = true,
    );
    expect(result.embeddedUrls.map((item) => item.reputation.availability), [
      ReputationAvailability.available,
      ReputationAvailability.unavailable,
      ReputationAvailability.unknown,
    ]);
    expect(result.showParentReputation, isFalse);
  });

  test('URL-free QR types do not need reputation notices', () {
    for (final type in [
      'phone',
      'phone_text',
      'wifi',
      'text',
      'sms',
      'email',
    ]) {
      final json = analysisResponse(qrType: type);
      // Recipients, subjects and SSIDs may appear in public extraction fields.
      json['extracted_urls'] = ['https://subject.invalid'];
      json['contains_url'] = true;
      expect(
        AnalysisResult.fromJson(json).showParentReputation,
        isFalse,
        reason: type,
      );
    }
  });

  test('legacy URL-bearing text shows its unknown parent lookup state', () {
    final json = analysisResponse(qrType: 'text_with_url')
      ..['contains_url'] = true
      ..remove('vt_available')
      ..remove('embedded_url_analysis_complete');
    final result = AnalysisResult.fromJson(json);
    expect(result.showParentReputation, isTrue);
    expect(result.embeddedAnalysisComplete, isNull);
    expect(result.reputation.availability, ReputationAvailability.unknown);
  });

  test('failure and skipped counts use separate response fields', () {
    final json = withEmbeddedUrls([embeddedResponse()])
      ..addAll({
        'embedded_url_count': 5,
        'embedded_url_analysis_complete': false,
        'analysis_flags': {'embedded_url_skipped_count': 2},
        'embedded_url_failures': [
          {
            'analysis_url': 'https://failed.invalid',
            'error_code': 'EMBEDDED_URL_ANALYSIS_FAILED',
            'error': 'Traceback secret-key',
          },
        ],
      });
    final result = AnalysisResult.fromJson(json);
    expect(result.isIncomplete, isTrue);
    expect(result.skippedEmbeddedUrlCount, 2);
    expect(
      result.embeddedFailures.single.analysisUrl,
      'https://failed.invalid',
    );
    expect(
      result.embeddedFailures.single.errorCode,
      'EMBEDDED_URL_ANALYSIS_FAILED',
    );
    expect(result.embeddedUrls.single.score, 10);
  });

  test('legacy missing optional lists do not break core result parsing', () {
    final json = analysisResponse();
    for (final key in [
      'embedded_url_results',
      'embedded_url_failures',
      'embedded_url_count',
      'analyzed_embedded_url_count',
      'embedded_url_analysis_complete',
    ]) {
      json.remove(key);
    }
    final result = AnalysisResult.fromJson(json);
    expect(result.riskScore, 10);
    expect(result.embeddedUrls, isEmpty);
    expect(result.embeddedAnalysisComplete, isNull);
    expect(result.skippedEmbeddedUrlCount, isNull);
  });

  test(
    'developer VT details become generic user reasons for parent and child',
    () {
      const reason = 'VirusTotal 조회 결과 미사용: .env VIRUSTOTAL_API_KEY=secret';
      final result = AnalysisResult.fromJson(
        withEmbeddedUrls([
          embeddedResponse()..['reasons'] = [reason],
        ])..['reasons'] = [reason],
      );
      for (final reasons in [
        result.reasons,
        result.embeddedUrls.single.reasons,
      ]) {
        expect(reasons.join(), isNot(contains('VIRUSTOTAL_API_KEY')));
        expect(reasons.join(), isNot(contains('secret')));
      }
      expect(riskStatusLabel(result.status), '낮은 위험');
      expect(result.displayMessage, isNot(contains('비교적 안전한')));
    },
  );

  test('invalid core response still fails with FormatException', () {
    for (final bytes in [
      utf8.encode('[]'),
      utf8.encode('{bad json'),
      utf8.encode(jsonEncode(analysisResponse()..['status'] = 'unknown')),
      utf8.encode(jsonEncode(analysisResponse()..['risk_score'] = '10')),
    ]) {
      expect(() => AnalysisResult.fromBodyBytes(bytes), throwsFormatException);
    }
  });
}
