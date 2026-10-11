part of 'main.dart';

class AnalysisResultView extends StatelessWidget {
  final AnalysisResult result;
  final ValueChanged<LinkActionTarget>? onOpenLink;
  final VoidCallback? onComposeSms;
  final bool smsAvailable;
  final bool actionsBusy;

  const AnalysisResultView({
    super.key,
    required this.result,
    this.onOpenLink,
    this.onComposeSms,
    this.smsAvailable = false,
    this.actionsBusy = false,
  });

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
          _riskOverview(),
          const SizedBox(height: 14),
          _card([
            _iconText(Icons.qr_code_rounded, '스캔 정보', color: AppColors.accent),
            const SizedBox(height: 12),
            _iconText(Icons.qr_code_rounded, qrTypeLabel(result.qrType)),
            if (result.preview.isNotEmpty) ...[
              const SizedBox(height: 6),
              SelectableText(result.preview, style: _bodyStyle),
            ],
            if (result.qrType == 'url' && result.url != null) ...[
              const SizedBox(height: 8),
              _address('분석 주소', result.url!),
            ],
            if (onOpenLink != null)
              _linkAction(LinkActionTarget.direct(result), 'open-direct-url'),
            if (result.qrType == 'sms' && onComposeSms != null) _smsAction(),
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
          if (result.reasons.isNotEmpty) ...[
            const SizedBox(height: 12),
            _card([_reasonList(result.reasons)]),
          ],
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
    fontSize: 14,
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
    if (onOpenLink != null)
      _linkAction(LinkActionTarget.embedded(item), 'open-embedded-$index'),
  ], key: ValueKey('embedded-result-$index'));

  Widget _linkAction(LinkActionTarget? target, String key) {
    if (target == null) return const SizedBox.shrink();
    final blocked = result.status == 'danger' || target.status == 'danger';
    return Padding(
      padding: const EdgeInsets.only(top: 12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          if (blocked)
            _iconText(
              Icons.block_rounded,
              '위험 판정으로 링크 열기를 제한했습니다.',
              color: AppColors.danger,
            ),
          OutlinedButton.icon(
            key: ValueKey(key),
            onPressed: blocked || actionsBusy
                ? null
                : () => onOpenLink!(target),
            icon: const Icon(Icons.open_in_new_rounded),
            label: const Text('링크 열기'),
          ),
        ],
      ),
    );
  }

  Widget _smsAction() {
    final blocked = result.status == 'danger';
    return Padding(
      padding: const EdgeInsets.only(top: 12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          if (blocked)
            _iconText(
              Icons.block_rounded,
              '위험 판정으로 문자 작성을 제한했습니다.',
              color: AppColors.danger,
            )
          else if (!smsAvailable)
            _iconText(
              Icons.info_outline_rounded,
              '수신 번호 또는 문자 형식을 확인할 수 없어 문자 작성을 제한했습니다.',
            ),
          if (smsAvailable)
            OutlinedButton.icon(
              key: const Key('compose-sms'),
              onPressed: blocked || actionsBusy ? null : onComposeSms,
              icon: const Icon(Icons.sms_outlined),
              label: const Text('문자 작성'),
            ),
        ],
      ),
    );
  }

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

  Widget _reputation(UrlReputation reputation) =>
      _notice(Icons.info_outline_rounded, reputationNoticeText(reputation));

  Color _statusColor(String? status) => switch (status) {
    'safe' => AppColors.safe,
    'warning' => AppColors.warning,
    'danger' => AppColors.danger,
    _ => AppColors.textHint,
  };

  Widget _riskOverview() {
    final color = _statusColor(result.status);
    return Container(
      key: const Key('risk-overview'),
      width: double.infinity,
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 24),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(24),
        gradient: LinearGradient(
          begin: Alignment.topCenter,
          end: Alignment.bottomCenter,
          colors: [color.withValues(alpha: 0.14), AppColors.bg],
        ),
      ),
      child: Column(
        children: [
          LayoutBuilder(
            builder: (context, constraints) {
              final diameter = math.min(
                constraints.maxWidth,
                MediaQuery.textScalerOf(
                  context,
                ).scale(156).clamp(156, 240).toDouble(),
              );
              return Semantics(
                label: '위험 점수 ${result.riskScore}. 악성 확률이 아닙니다.',
                excludeSemantics: true,
                child: SizedBox.square(
                  key: const Key('risk-score-ring'),
                  dimension: diameter,
                  child: Stack(
                    alignment: Alignment.center,
                    children: [
                      Positioned.fill(
                        child: CircularProgressIndicator(
                          value:
                              result.riskScore.toDouble().clamp(0, 100) / 100,
                          color: color,
                          backgroundColor: color.withValues(alpha: 0.16),
                          strokeWidth: 10,
                          strokeCap: StrokeCap.round,
                        ),
                      ),
                      Padding(
                        padding: const EdgeInsets.all(20),
                        child: FittedBox(
                          fit: BoxFit.scaleDown,
                          child: Text(
                            '${result.riskScore}',
                            key: const Key('risk-score-value'),
                            style: TextStyle(
                              fontSize: 44,
                              fontWeight: FontWeight.w800,
                              color: color,
                            ),
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              );
            },
          ),
          const SizedBox(height: 12),
          Text(
            '위험 점수 ${result.riskScore}',
            textAlign: TextAlign.center,
            style: _bodyStyle.copyWith(
              color: color,
              fontWeight: FontWeight.w700,
            ),
          ),
          const SizedBox(height: 12),
          _riskSummary(result.status, result.riskScore, showScore: false),
          const SizedBox(height: 12),
          const Text(
            '점수는 악성 확률이나 신뢰도 퍼센트가 아닙니다.',
            textAlign: TextAlign.center,
            style: _bodyStyle,
          ),
        ],
      ),
    );
  }

  Widget _riskSummary(String? status, num? score, {bool showScore = true}) {
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
        if (showScore)
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
    padding: const EdgeInsets.all(18),
    decoration: BoxDecoration(
      color: AppColors.surface,
      borderRadius: BorderRadius.circular(18),
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
