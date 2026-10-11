import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter/services.dart';
import 'package:qr_phishing_app/analysis_result.dart';
import 'package:qr_phishing_app/result_actions.dart';

import 'fixtures/analysis_responses.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test(
    'system adapter passes exact strings to external mode without a WebView',
    () async {
      const channel = MethodChannel('plugins.flutter.io/url_launcher');
      final calls = <MethodCall>[];
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async {
            calls.add(call);
            return true;
          });
      addTearDown(
        () => TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(channel, null),
      );
      final addresses = [
        'https://example.invalid/a/../AbC?Token=Ab%2fCd&x=%26%3D%3F%2B',
        'https://example.com:8443/배송조회?Token=Ab%26Cd+E#조각%23',
        const SmsDraft('+821012345678', '한글 & ? = +').address,
      ];
      for (final address in addresses) {
        expect(await const SystemExternalAppLauncher().open(address), isTrue);
        expect(calls.last.method, 'launch');
        final arguments = calls.last.arguments as Map;
        expect(arguments['url'], address);
        expect(arguments['useWebView'], isFalse);
        expect(arguments['useSafariVC'], isFalse);
      }
      expect(calls, hasLength(addresses.length));
    },
  );

  test('web actions validate without decoding or rewriting the address', () {
    for (final address in [
      'https://example.invalid/AbC?Token=Ab%2fCd&x=%26%3D%3F%2B',
      'http://example.invalid/a/../B?Case=A+B#Part',
      'HTTPS://EXAMPLE.INVALID/Path',
      'https://[::1]:8443/Path',
      'https://example.com:8443/배송조회?Token=Ab%26Cd+E#조각%23',
    ]) {
      expect(isLaunchableWebAddress(address), isTrue, reason: address);
      final result = AnalysisResult.fromJson(
        analysisResponse()..['url'] = address,
      );
      expect(LinkActionTarget.direct(result)!.address, address);
    }
    for (final address in [
      '',
      'example.invalid',
      '//example.invalid',
      'https:///Path',
      'javascript:alert(1)',
      'data:text/html,hello',
      'file:///tmp/a',
      'intent://example.invalid',
      'ftp://example.invalid',
      'https://user:password@example.invalid',
      'https://@example.invalid',
      'https://%75ser%40example.invalid',
      'https://example.invalid:wrong',
      'https://example.invalid:99999',
      'https://example.invalid/%wrong',
      'https://example.invalid/hello world',
      'https://example.invalid\\evil',
      'https://example.invalid/\nPath',
    ]) {
      expect(isLaunchableWebAddress(address), isFalse, reason: address);
    }
  });

  test('only successful child metadata supplies its own analyzed target', () {
    final json = embeddedResponse(url: 'https://child.invalid/Path')
      ..addAll({
        'original_url': 'child.invalid/Path',
        'original_candidates': ['child.invalid/Path'],
        'assumed_https': true,
      });
    final target = LinkActionTarget.embedded(
      EmbeddedUrlAnalysis.fromJson(json),
    )!;
    expect(target.address, 'https://child.invalid/Path');
    expect(target.originalCandidates, ['child.invalid/Path']);
    expect(target.assumedHttps, isTrue);
    for (final fields in [
      {'risk_score': null, 'final_score': null},
      {'status': null},
      {'analysis_url': ''},
      {'analysis_url': 'https://user@child.invalid'},
    ]) {
      expect(
        LinkActionTarget.embedded(
          EmbeddedUrlAnalysis.fromJson({...json, ...fields}),
        ),
        isNull,
      );
    }
    expect(
      LinkActionTarget.direct(
        AnalysisResult.fromJson(
          withEmbeddedUrls([json])..['url'] = 'https://parent.invalid',
        ),
      ),
      isNull,
    );
  });

  test(
    'SMS supported forms preserve field boundaries, Hangul and reserved values',
    () {
      const body = '한글 + & ? = :\nhttps://example.invalid/Path?A=B&C=D+E 100%';
      for (final raw in [
        'SMS:+821012345678?subject=제목:콜론&body=${Uri.encodeComponent(body)}',
        'smsto:%2B821012345678:${Uri.encodeComponent(body)}',
        'sms:+821012345678:$body',
      ]) {
        final draft = parseSmsDraft(raw)!;
        expect(draft.recipient, '+821012345678');
        expect(draft.body, body);
        expect(draft.address.startsWith('sms:+821012345678?body='), isTrue);
        expect(Uri.decodeComponent(draft.address.split('?body=')[1]), body);
        expect(draft.address, contains('%2B'));
        expect(draft.address, contains('%26'));
        expect(draft.address, contains('%3F'));
        expect(draft.address, contains('%3D'));
        expect(draft.address, contains('%20'));
      }
      expect(
        parseSmsDraft('sms:010-1234-5678:hello?x=a&y=b=c+z')!.body,
        'hello?x=a&y=b=c+z',
      );
      expect(
        parseSmsDraft('sms:01012345678?body=hello+world%2B')!.body,
        'hello world+',
      );
      expect(
        parseSmsDraft('sms:01012345678?body=a%2526b%253Dc%253Fd')!.body,
        'a&b=c?d',
      );
    },
  );

  test('SMS drafts match backend analysis bodies and preserve URL escapes', () {
    // Generated and checked against the real offline backend analysis body
    // and extractors at the commit recorded in this fixture, not its preview.
    final fixture =
        jsonDecode(
              File('test/fixtures/sms_analysis_bodies.json').readAsStringSync(),
            )
            as Map<String, dynamic>;
    for (final item in fixture['cases'] as List) {
      final draft = parseSmsDraft(item['raw'] as String);
      expect(draft, isNotNull, reason: item['name'] as String);
      expect(draft!.body, item['body'], reason: item['name'] as String);
      // The OS removes just the SMS URI's outer encoding. The analyzed URL's
      // escapes, casing, Unicode and delimiters must remain in that body.
      expect(
        Uri.decodeComponent(draft.address.split('?body=')[1]),
        item['body'],
        reason: item['name'] as String,
      );
      for (final url in [
        ...item['urls'] as List,
        ...item['candidates'] as List,
      ]) {
        expect(draft.body, contains(url), reason: item['name'] as String);
      }
    }
    final draft = parseSmsDraft(
      'smsto:01012340000:https://example.com/path?next=%26admin%3D1',
    )!;
    expect(
      draft.address,
      'sms:01012340000?body=https%3A%2F%2Fexample.com%2Fpath%3Fnext%3D%2526admin%253D1',
    );
  });

  test(
    'first explicit empty query body wins and subject colons are not delimiters',
    () {
      for (final raw in [
        'sms:01012345678?subject=title:message&body=&body=ignored',
        'sms:01012345678?body&subject=:message',
        'SMSTO:01012345678:',
        'SMS:01012345678:',
        'sms:01012345678',
      ]) {
        final draft = parseSmsDraft(raw)!;
        expect(draft.body, '');
        expect(draft.address, 'sms:01012345678?body=');
      }
      expect(parseSmsDraft('sms:01012345678?subject=title:message')!.body, '');
      // Backend leaves this mixed-form colon in the recipient when query body
      // exists. Do not guess that stripping it would recover a valid destination.
      expect(parseSmsDraft('sms:01012345678:ignored?body='), isNull);
      expect(parseSmsDraft('sms:01012345678%3Aother?body=hello'), isNull);
    },
  );

  test('masked, multiple, invalid and ambiguous recipients cannot compose', () {
    for (final raw in [
      'sms:010****5678?body=hello',
      'sms:010XXXX5678:hello',
      'sms:01012345678,01098765432:hello',
      'sms:01012345678%2C01098765432?body=hello',
      'smsto:01012345678;01098765432:hello',
      'sms:tel:01012345678',
      'sms:hello.invalid:message',
      'sms:123:hello',
      'sms:+1234567890123456:hello',
      'sms://01012345678?body=hello',
      'sms:01012345678%3Fbody=hello',
      'sms:01012345678?body=%FF',
      'sms:01012345678?body=%00',
      'sms%3A01012345678%3Ahello',
      'mailto:01012345678?body=hello',
    ]) {
      expect(parseSmsDraft(raw), isNull, reason: raw);
    }
  });
}
