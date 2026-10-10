part of 'main.dart';

class AnalysisResultView extends StatelessWidget {
  final AnalysisResult result;

  const AnalysisResultView({super.key, required this.result});

  @override
  Widget build(BuildContext context) {
    return SingleChildScrollView(
      key: const Key('analysis-result-scroll'),
      padding: const EdgeInsets.fromLTRB(20, 20, 20, 16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          if (result.isIncomplete) ...[
            _notice(
              Icons.warning_rounded,
              '일부 링크의 분석을 완료하지 못했습니다.',
              color: AppColors.warning,
              background: AppColors.warningBg,
            ),
            const SizedBox(height: 12),
          ],
          _riskSummary(result.status, result.riskScore),
          const SizedBox(height: 14),
          _card([
            _iconText(Icons.qr_code_rounded, qrTypeLabel(result.qrType)),
            if (result.preview.isNotEmpty) ...[
              const SizedBox(height: 6),
              Text(result.preview, style: _bodyStyle),
            ],
            if (result.qrType == 'url' && result.url != null) ...[
              const SizedBox(height: 8),
              _address('분석 주소', result.url!),
            ],
          ]),
          const SizedBox(height: 12),
          Text(result.displayMessage, style: _bodyStyle),
          if (result.showParentReputation) ...[
            const SizedBox(height: 12),
            _reputation(result.reputation),
          ],
          if (result.hasEmbeddedTargets) ...[
            const SizedBox(height: 12),
            _iconText(Icons.link_rounded, '포함 링크의 외부 평판 상태는 각 링크에서 확인하세요.'),
          ],
          if (result.isIncomplete) ...[
            const SizedBox(height: 12),
            if ((result.skippedEmbeddedUrlCount ?? 0) > 0)
              _iconText(
                Icons.more_horiz_rounded,
                '분석 개수 제한으로 ${result.skippedEmbeddedUrlCount}개 링크를 검사하지 못했습니다.',
              ),
            if (result.embeddedFailures.isNotEmpty)
              _iconText(
                Icons.error_outline_rounded,
                '${result.embeddedFailures.length}개 링크의 분석에 실패했습니다.',
              ),
            if (result.skippedEmbeddedUrlCount == null &&
                result.embeddedFailures.isEmpty)
              _iconText(
                Icons.info_outline_rounded,
                '응답에 분석 미완료 사유의 상세 정보가 없습니다.',
              ),
            if (result.embeddedUrlCount != null &&
                result.analyzedEmbeddedUrlCount != null)
              Text(
                '포함 링크 ${result.embeddedUrlCount}개 중 ${result.analyzedEmbeddedUrlCount}개 분석 완료',
                style: _bodyStyle,
              ),
          ],
          _reasonList(result.reasons),
          if (result.embeddedUrls.isNotEmpty) ...[
            const SizedBox(height: 16),
            _sectionTitle('포함 URL 분석 결과'),
            for (
              var index = 0;
              index < result.embeddedUrls.length;
              index++
            ) ...[
              const SizedBox(height: 10),
              _embeddedResult(result.embeddedUrls[index], index),
            ],
          ],
          if (result.embeddedFailures.isNotEmpty) ...[
            const SizedBox(height: 16),
            _sectionTitle('분석하지 못한 링크'),
            for (
              var index = 0;
              index < result.embeddedFailures.length;
              index++
            ) ...[
              const SizedBox(height: 10),
              _failedResult(result.embeddedFailures[index], index),
            ],
          ],
        ],
      ),
    );
  }

  static const _bodyStyle = TextStyle(
    fontSize: 13,
    color: AppColors.textSec,
    height: 1.6,
  );

  Widget _embeddedResult(EmbeddedUrlAnalysis item, int index) => _card([
    _sectionTitle('링크 ${index + 1}'),
    const SizedBox(height: 8),
    _target(item),
    const SizedBox(height: 12),
    _riskSummary(item.status, item.score),
    _reasonList(item.reasons),
    const SizedBox(height: 12),
    _reputation(item.reputation),
  ], key: ValueKey('embedded-result-$index'));

  Widget _failedResult(EmbeddedUrlFailure item, int index) => _card([
    _iconText(Icons.error_outline_rounded, '링크 분석 실패'),
    const SizedBox(height: 8),
    _target(item),
    const SizedBox(height: 8),
    Text(
      item.errorCode == 'EMBEDDED_URL_ANALYSIS_FAILED'
          ? '이 링크의 분석을 완료하지 못해 위험 점수와 평판 상태를 확인할 수 없습니다.'
          : '이 링크의 분석 결과를 확인할 수 없습니다.',
      style: _bodyStyle,
    ),
  ], key: ValueKey('embedded-failure-$index'));

  Widget _target(EmbeddedUrlTarget item) => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      if (item.assumedHttps) ...[
        if (item.originalCandidates.isNotEmpty)
          for (final candidate in item.originalCandidates)
            _address('원본 후보', candidate)
        else if (item.originalUrl.isNotEmpty)
          _address('원본 후보', item.originalUrl),
      ],
      _address(
        '분석 주소',
        item.analysisUrl.isNotEmpty ? item.analysisUrl : '주소 정보 없음',
      ),
      if (item.assumedHttps) ...[
        const SizedBox(height: 8),
        _notice(
          Icons.info_outline_rounded,
          '분석을 위해 HTTPS를 가정했습니다. 실제 HTTPS 지원 여부는 확인하지 않았습니다.',
        ),
      ],
    ],
  );

  Widget _reputation(UrlReputation reputation) {
    final title = switch (reputation.availability) {
      ReputationAvailability.available => '외부 평판 정보 있음',
      ReputationAvailability.unavailable => '외부 평판 정보 없음',
      ReputationAvailability.unknown => '조회 상태 확인 불가',
    };
    final lookupMessage = switch (reputation.lookupStatus) {
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
    final sourceMessage = switch (reputation.source) {
      ReputationSource.requestedReport =>
        '이번 요청에서 외부 리포트를 조회했습니다. 리포트의 분석 시각은 조회 시각과 다를 수 있습니다.',
      ReputationSource.storedReport => '저장된 평판 정보이며 최신 상태와 다를 수 있습니다.',
      ReputationSource.historicalReport =>
        '이번 외부 평판 조회는 완료되지 않았습니다. 점수에 과거 평판 정보를 사용했으며 최신 상태와 다를 수 있습니다.',
      ReputationSource.unknown => '평판 정보의 출처를 확인할 수 없습니다.',
    };
    final historical = reputation.historicalReputationUsed;
    final lines = [
      lookupMessage,
      sourceMessage,
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
    ];
    return _notice(Icons.info_outline_rounded, '$title\n${lines.join('\n')}');
  }

  Widget _riskSummary(String? status, num? score) {
    final color = switch (status) {
      'safe' => AppColors.safe,
      'warning' => AppColors.warning,
      'danger' => AppColors.danger,
      _ => AppColors.textHint,
    };
    final background = switch (status) {
      'safe' => AppColors.safeBg,
      'warning' => AppColors.warningBg,
      'danger' => AppColors.dangerBg,
      _ => AppColors.surfaceSub,
    };
    final icon = switch (status) {
      'safe' => Icons.info_outline_rounded,
      'warning' => Icons.warning_rounded,
      'danger' => Icons.dangerous_rounded,
      _ => Icons.help_outline_rounded,
    };
    // Wrap rather than a fixed horizontal row: narrow screens and larger text
    // can move the score onto its own line without changing the decision.
    return Wrap(
      spacing: 10,
      runSpacing: 8,
      children: [
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 7),
          decoration: BoxDecoration(
            color: background,
            borderRadius: BorderRadius.circular(20),
            border: Border.all(color: color.withValues(alpha: 0.3)),
          ),
          child: _iconText(icon, riskStatusLabel(status), color: color),
        ),
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 7),
          decoration: BoxDecoration(
            color: AppColors.surfaceSub,
            borderRadius: BorderRadius.circular(20),
          ),
          child: Text(
            score == null ? '위험 점수 확인 불가' : '위험 점수 $score',
            style: _bodyStyle.copyWith(
              color: color,
              fontWeight: FontWeight.w700,
            ),
          ),
        ),
      ],
    );
  }

  Widget _reasonList(List<String> reasons) => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      if (reasons.isNotEmpty) ...[
        const SizedBox(height: 12),
        _sectionTitle('판단 사유'),
        for (final reason in reasons)
          Padding(
            padding: const EdgeInsets.only(top: 5),
            child: _iconText(Icons.chevron_right_rounded, reason),
          ),
      ],
    ],
  );

  Widget _address(String label, String value) => Padding(
    padding: const EdgeInsets.only(top: 4),
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(label, style: _bodyStyle.copyWith(color: AppColors.textHint)),
        // No URI interaction: addresses remain plain, selectable display text.
        SelectableText(value, style: _bodyStyle),
      ],
    ),
  );

  Widget _sectionTitle(String text) =>
      Text(text, style: _bodyStyle.copyWith(fontWeight: FontWeight.w600));

  Widget _card(List<Widget> children, {Key? key}) => Container(
    key: key,
    width: double.infinity,
    padding: const EdgeInsets.all(14),
    decoration: BoxDecoration(
      color: AppColors.surfaceSub,
      borderRadius: BorderRadius.circular(12),
      border: Border.all(color: AppColors.border),
    ),
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: children,
    ),
  );

  Widget _notice(
    IconData icon,
    String text, {
    Color color = AppColors.accent,
    Color background = AppColors.accentBg,
  }) => Container(
    width: double.infinity,
    padding: const EdgeInsets.all(12),
    decoration: BoxDecoration(
      color: background,
      borderRadius: BorderRadius.circular(12),
    ),
    child: _iconText(icon, text, color: color),
  );

  Widget _iconText(
    IconData icon,
    String text, {
    Color color = AppColors.textSec,
  }) => Row(
    mainAxisSize: MainAxisSize.min,
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      Icon(icon, size: 18, color: color),
      const SizedBox(width: 6),
      Flexible(
        child: Text(text, style: _bodyStyle.copyWith(color: color)),
      ),
    ],
  );
}
