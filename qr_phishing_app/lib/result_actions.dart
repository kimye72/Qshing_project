import 'package:url_launcher/url_launcher_string.dart';

import 'analysis_result.dart';

// An injectable boundary: tests never start a browser or a messaging app.
abstract class ExternalAppLauncher {
  Future<bool> open(String address);
}

class SystemExternalAppLauncher implements ExternalAppLauncher {
  const SystemExternalAppLauncher();

  @override
  Future<bool> open(String address) =>
      launchUrlString(address, mode: LaunchMode.externalApplication);
}

// Parse only to validate. Pass the original analyzed string to the launcher:
// Uri serialization can normalize dot segments or percent escapes in a URL.
bool isLaunchableWebAddress(String address) {
  if (address.isEmpty ||
      RegExp(r'[\x00-\x20\x7f\\]').hasMatch(address) ||
      RegExp(r'%(?![0-9a-fA-F]{2})').hasMatch(address)) {
    return false;
  }
  try {
    final separator = address.indexOf('://');
    if (separator < 0) return false;
    final rawAuthority = address
        .substring(separator + 3)
        .split(RegExp(r'[/\?#]'))
        .first;
    // Uri may discard an explicitly empty userinfo; inspect raw authority too.
    if (rawAuthority.contains('@')) return false;
    final uri = Uri.parse(address);
    if (!{'http', 'https'}.contains(uri.scheme) ||
        !uri.hasAuthority ||
        uri.host.isEmpty ||
        uri.userInfo.isNotEmpty ||
        uri.authority.contains('@') ||
        uri.host.contains('%')) {
      return false;
    }
    // Accessing port also validates a malformed authority/port.
    if (uri.port < 1 || uri.port > 65535) return false;
    return true;
  } on FormatException {
    return false;
  }
}

class LinkActionTarget {
  final String address;
  final String status;
  final UrlReputation reputation;
  final bool assumedHttps;
  final List<String> originalCandidates;

  const LinkActionTarget({
    required this.address,
    required this.status,
    required this.reputation,
    this.assumedHttps = false,
    this.originalCandidates = const [],
  });

  static LinkActionTarget? direct(AnalysisResult result) =>
      result.qrType == 'url' &&
          result.url != null &&
          isLaunchableWebAddress(result.url!)
      ? LinkActionTarget(
          address: result.url!,
          status: result.status,
          reputation: result.reputation,
        )
      : null;

  static LinkActionTarget? embedded(EmbeddedUrlAnalysis item) =>
      item.score != null &&
          item.status != null &&
          isLaunchableWebAddress(item.analysisUrl)
      ? LinkActionTarget(
          address: item.analysisUrl,
          status: item.status!,
          reputation: item.reputation,
          assumedHttps: item.assumedHttps,
          originalCandidates: item.originalCandidates.isNotEmpty
              ? item.originalCandidates
              : [if (item.originalUrl.isNotEmpty) item.originalUrl],
        )
      : null;
}

class SmsDraft {
  final String recipient;
  final String body;

  const SmsDraft(this.recipient, this.body);

  // Encode each value once, without queryParameters' space-to-plus conversion.
  // An explicit empty body stays present; composing never sends an SMS.
  String get address => 'sms:$recipient?body=${Uri.encodeComponent(body)}';
}

String _decodeRepeatedly(String value, {int rounds = 3}) {
  for (var round = 0; round < rounds; round++) {
    // Python unquote preserves a literal/malformed percent sign. Reject bad
    // UTF-8 rather than guess at an executable recipient or message.
    final encoded = StringBuffer();
    var end = 0;
    for (final match in RegExp(r'%[0-9a-fA-F]{2}').allMatches(value)) {
      encoded.write(Uri.encodeComponent(value.substring(end, match.start)));
      encoded.write(match.group(0));
      end = match.end;
    }
    encoded.write(Uri.encodeComponent(value.substring(end)));
    final decoded = Uri.decodeComponent(encoded.toString());
    if (decoded == value) break;
    value = decoded;
  }
  return value;
}

// Same token boundaries as qr_analyzer.URL_PATTERN/URL_CANDIDATE_PATTERN
// (embedded URL policy 2.1). These spans protect message text; they do not
// validate executable URLs or turn candidates into HTTPS addresses.
final _visibleBodyUrl = RegExp(
  r'''https?://[^\s<>'"]+''',
  caseSensitive: false,
);
final _bodyUrlCandidate = RegExp(
  r'''(?<![A-Za-z0-9@._-])(?<candidate>(?<domain>(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+(?:[A-Za-z]{2,63}|xn--[A-Za-z0-9-]{2,59}))(?<port>:[^/\s<>'"?#]*)?(?<path>/[^\s<>'"?#]*)?(?<query>\?[^\s<>'"#]*)?(?<fragment>\#[^\s<>'"]*)?)(?![A-Za-z0-9_:%-]|\.[A-Za-z0-9_-])''',
  caseSensitive: false,
);

String _decodeLinkBody(String value, {int rounds = 3}) {
  // Reveal encoded wrappers only until URL structure is visible. On each pass
  // decode prose once and copy URL spans verbatim, including nested escapes.
  // Match the backend analysis body, not its repeatedly decoded masked preview.
  for (var round = 0; round < rounds; round++) {
    final spans =
        [
          ..._visibleBodyUrl.allMatches(value),
          ..._bodyUrlCandidate
              .allMatches(value)
              .where(
                (match) => [
                  'port',
                  'path',
                  'query',
                  'fragment',
                ].any((name) => match.namedGroup(name) != null),
              ),
        ]..sort((a, b) {
          final start = a.start.compareTo(b.start);
          return start == 0 ? a.end.compareTo(b.end) : start;
        });
    final pieces = StringBuffer();
    var end = 0;
    for (final span in spans) {
      if (span.start < end) continue;
      pieces.write(
        _decodeRepeatedly(value.substring(end, span.start), rounds: 1),
      );
      pieces.write(value.substring(span.start, span.end));
      end = span.end;
    }
    pieces.write(_decodeRepeatedly(value.substring(end), rounds: 1));
    final decoded = pieces.toString();
    if (decoded == value) break;
    value = decoded;
  }
  return value;
}

String? _queryBody(String query) {
  for (final field in query.split('&')) {
    final equals = field.indexOf('=');
    final rawKey = equals < 0 ? field : field.substring(0, equals);
    final key = _decodeRepeatedly(rawKey.replaceAll('+', ' '), rounds: 1);
    if (key != 'body') continue;
    final rawValue = equals < 0 ? '' : field.substring(equals + 1);
    // parse_qs performs one outer form pass before protecting visible URLs.
    final first = _decodeRepeatedly(rawValue.replaceAll('+', ' '), rounds: 1);
    return _decodeLinkBody(first, rounds: 2);
  }
  return null;
}

// Mirrors qr_analyzer._parse_sms_payload(preserve_url_encoding: true), used by
// _extract_structured_body for analysis. Additional recipient validation is
// intentional: a masking helper is not an action parser.
SmsDraft? parseSmsDraft(String raw) {
  final content = raw.trim();
  final lower = content.toLowerCase();
  String recipient;
  String? body;
  try {
    if (lower.startsWith('smsto:')) {
      final payload = content.substring(6);
      final colon = payload.indexOf(':');
      recipient = colon < 0 ? payload : payload.substring(0, colon);
      body = colon < 0 ? null : _decodeLinkBody(payload.substring(colon + 1));
    } else if (lower.startsWith('sms:')) {
      final payload = content.substring(4);
      final question = payload.indexOf('?');
      recipient = question < 0 ? payload : payload.substring(0, question);
      body = question < 0 ? null : _queryBody(payload.substring(question + 1));
      if (body == null && recipient.contains(':')) {
        final colon = payload.indexOf(':');
        recipient = payload.substring(0, colon);
        body = _decodeLinkBody(payload.substring(colon + 1));
      }
    } else {
      return null;
    }
    recipient = _decodeRepeatedly(recipient);
    // One numeric recipient only. No masks, aliases, comma/semicolon lists,
    // URI fields or decoded colons; no attempt to reconstruct missing digits.
    if (!RegExp(r'^\+?[0-9]+(?:[ -][0-9]+)*$').hasMatch(recipient)) return null;
    final number = recipient.replaceAll(RegExp(r'[ -]'), '');
    if (!RegExp(r'^\+?[0-9]{7,15}$').hasMatch(number)) return null;
    if (body != null &&
        RegExp(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]').hasMatch(body)) {
      return null;
    }
    return SmsDraft(number, body ?? '');
  } on FormatException {
    return null;
  } on ArgumentError {
    return null;
  }
}

// Shared by the result card and the confirmation: lookup and source stay
// separate, and historical counts never become current zero detections.
String reputationNoticeText(UrlReputation reputation) {
  final title = switch (reputation.availability) {
    ReputationAvailability.available => '외부 평판 정보 있음',
    ReputationAvailability.unavailable => '외부 평판 정보 없음',
    ReputationAvailability.unknown => '조회 상태 확인 불가',
  };
  final lookup = switch (reputation.lookupStatus) {
    ReputationLookupStatus.available => '외부 리포트 조회 완료',
    ReputationLookupStatus.cached => '저장된 리포트를 재사용했습니다.',
    ReputationLookupStatus.lookupFailed => '외부 평판을 조회하지 못했습니다.',
    ReputationLookupStatus.timeout => '외부 평판 조회 시간이 초과되었습니다.',
    ReputationLookupStatus.budgetExhausted => '분석 시간 안에 외부 평판을 확인하지 못했습니다.',
    ReputationLookupStatus.rateLimited => '외부 평판 조회가 일시적으로 제한되었습니다.',
    ReputationLookupStatus.reportMissing => '이 주소의 외부 평판 리포트가 없습니다.',
    ReputationLookupStatus.submitted => '분석 요청이 접수되었지만 리포트는 아직 확인되지 않았습니다.',
    ReputationLookupStatus.disabled => '외부 평판 조회를 사용하지 않았습니다.',
    ReputationLookupStatus.unknown => '평판 조회 상태를 확인할 수 없습니다.',
  };
  final source = switch (reputation.source) {
    ReputationSource.requestedReport =>
      '이번 요청에서 외부 리포트를 조회했습니다. 리포트의 분석 시각은 조회 시각과 다를 수 있습니다.',
    ReputationSource.storedReport => '저장된 평판 정보이며 최신 상태와 다를 수 있습니다.',
    ReputationSource.historicalReport =>
      '이번 외부 평판 조회는 완료되지 않았습니다. 점수에 과거 평판 정보를 사용했으며 최신 상태와 다를 수 있습니다.',
    ReputationSource.unknown => '평판 정보의 출처를 확인할 수 없습니다.',
  };
  final historical = reputation.historicalReputationUsed;
  return [
    title,
    lookup,
    source,
    if (historical && reputation.source != ReputationSource.historicalReport)
      '점수에 과거 평판 정보를 사용했습니다. 이번 조회의 완료 여부는 조회 상태 안내를 확인하세요.',
    if (reputation.availability == ReputationAvailability.available ||
        historical) ...[
      reputation.malicious == null
          ? '${historical ? '과거 ' : ''}악성 탐지 수 확인 불가'
          : '${historical ? '과거 ' : ''}악성 탐지 ${reputation.malicious}건',
      reputation.suspicious == null
          ? '${historical ? '과거 ' : ''}의심 탐지 수 확인 불가'
          : '${historical ? '과거 ' : ''}의심 탐지 ${reputation.suspicious}건',
    ],
    if (reputation.availability == ReputationAvailability.unavailable)
      '현재 확인한 정보만으로 평가한 결과입니다.',
    '외부 평판 정보는 실제 안전성을 보장하지 않습니다.',
  ].join('\n');
}
