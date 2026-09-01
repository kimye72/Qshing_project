import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:mobile_scanner/mobile_scanner.dart';

void main() {
  runApp(const QrPhishingApp());
}

// ── 색상 팔레트 ──────────────────────────────────────────
class AppColors {
  static const bg         = Color(0xFFF4F6FA);
  static const surface    = Color(0xFFFFFFFF);
  static const surfaceSub = Color(0xFFEEF1F7);
  static const border     = Color(0x14000000);
  static const textPrim   = Color(0xFF1A1D26);
  static const textSec    = Color(0xFF3A3F52);
  static const textHint   = Color(0xFF7A8099);

  static const safe       = Color(0xFF0E9E5A);
  static const safeBg     = Color(0x140E9E5A);
  static const warning    = Color(0xFFC47A00);
  static const warningBg  = Color(0x14C47A00);
  static const danger     = Color(0xFFD63030);
  static const dangerBg   = Color(0x12D63030);
  static const accent     = Color(0xFF2563EB);
  static const accentBg   = Color(0x102563EB);
}

// ── QR 유형 한글화 ───────────────────────────────────────
String qrTypeLabel(dynamic raw) {
  const map = {
    'url':              'URL',
    'text':             '일반 텍스트',
    'text_with_url':    'URL 포함 텍스트',
    'phone':            '전화번호',
    'phone_text':       '전화번호 포함 텍스트',
    'sms':              'SMS',
    'email':            '이메일',
    'email_text':       '이메일 포함 텍스트',
    'wifi':             'Wi-Fi',
    'dangerous_scheme': '위험 스킴',
  };
  return map[raw?.toString()] ?? '기타';
}

// ────────────────────────────────────────────────────────
class QrPhishingApp extends StatelessWidget {
  const QrPhishingApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'QR 피싱 방지 시스템',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        useMaterial3: true,
        colorSchemeSeed: AppColors.accent,
        scaffoldBackgroundColor: AppColors.bg,
        fontFamily: 'Pretendard',
        appBarTheme: const AppBarTheme(
          backgroundColor: AppColors.surface,
          foregroundColor: AppColors.textPrim,
          elevation: 0,
          centerTitle: true,
          titleTextStyle: TextStyle(
            color: AppColors.textPrim,
            fontSize: 17,
            fontWeight: FontWeight.w600,
            letterSpacing: -0.3,
          ),
        ),
      ),
      home: const ScanPage(),
    );
  }
}

// ────────────────────────────────────────────────────────
class ScanPage extends StatefulWidget {
  const ScanPage({super.key});

  @override
  State<ScanPage> createState() => _ScanPageState();
}

class _ScanPageState extends State<ScanPage> with TickerProviderStateMixin {
  final MobileScannerController _scannerController = MobileScannerController();

  bool _isProcessing = false;
  Map<String, dynamic>? _result = null;
  String? _errorMessage;

  late final AnimationController _pulseController = AnimationController(
    vsync: this,
    duration: const Duration(seconds: 2),
  )..repeat(reverse: true);

  late final Animation<double> _pulseAnim = Tween<double>(
    begin: 0.6, end: 1.0,
  ).animate(CurvedAnimation(parent: _pulseController, curve: Curves.easeInOut));

  static const String apiUrl = String.fromEnvironment(
    'API_URL',
    defaultValue: '',
  );
  static const Duration _apiTimeout = Duration(seconds: 15);

  String _httpErrorMessage(int statusCode) {
    if (statusCode == 400 || statusCode == 422) {
      return 'QR 내용을 분석할 수 없습니다.';
    }
    if (statusCode >= 500) {
      return '서버에서 오류가 발생했습니다.\n잠시 후 다시 시도해주세요.';
    }
    return 'QR 분석 중 오류가 발생했습니다.';
  }

  Map<String, dynamic> _parseAnalysisResponse(http.Response response) {
    final decodedBody = utf8.decode(response.bodyBytes);
    final decodedJson = jsonDecode(decodedBody);

    if (decodedJson is! Map) {
      throw const FormatException('Analysis response is not an object.');
    }

    final data = Map<String, dynamic>.from(decodedJson);
    const validStatuses = {'safe', 'warning', 'danger'};

    if (data['qr_type'] is! String ||
        data['raw_content_preview'] is! String ||
        data['risk_score'] is! num ||
        data['status'] is! String ||
        !validStatuses.contains(data['status']) ||
        data['message'] is! String ||
        data['reasons'] is! List) {
      throw const FormatException('Analysis response fields are invalid.');
    }

    return data;
  }

  // ── 기능 로직 (기존 그대로) ────────────────────────────
  Future<void> _analyzeQRContent(String qrContent) async {
    if (!mounted) return;

    if (apiUrl.trim().isEmpty) {
      setState(() {
        _errorMessage = 'API 서버 주소가 설정되지 않았습니다.';
        _result = null;
      });
      return;
    }

    setState(() {
      _isProcessing = true;
      _errorMessage = null;
      _result = null;
    });

    try {
      final response = await http.post(
        Uri.parse(apiUrl),
        headers: {'Content-Type': 'application/json; charset=utf-8'},
        body: jsonEncode({'content': qrContent}),
      ).timeout(_apiTimeout);

      if (!mounted) return;

      if (response.statusCode != 200) {
        setState(() {
          _errorMessage = _httpErrorMessage(response.statusCode);
        });
        return;
      }

      final data = _parseAnalysisResponse(response);

      if (!mounted) return;
      setState(() { _result = data; });
    } on TimeoutException {
      if (!mounted) return;
      setState(() {
        _errorMessage = '서버 응답 시간이 초과되었습니다.\n잠시 후 다시 시도해주세요.';
      });
    } on FormatException {
      if (!mounted) return;
      setState(() {
        _errorMessage = '분석 결과를 처리하는 중 오류가 발생했습니다.';
      });
    } on TypeError {
      if (!mounted) return;
      setState(() {
        _errorMessage = '분석 결과를 처리하는 중 오류가 발생했습니다.';
      });
    } catch (_) {
      if (!mounted) return;
      setState(() {
        _errorMessage = 'QR 분석 중 오류가 발생했습니다.';
      });
    } finally {
      if (mounted) {
        setState(() { _isProcessing = false; });
      }
    }
  }

  void _resetScan() {
    if (!mounted) return;

    setState(() {
      _result = null;
      _errorMessage = null;
      _isProcessing = false;
    });
    _scannerController.start();
  }

  @override
  void dispose() {
    _scannerController.dispose();
    _pulseController.dispose();
    super.dispose();
  }

  // ── 상태별 색상 / 텍스트 ─────────────────────────────
  Color _statusColor(String? s) {
    switch (s) {
      case 'safe':    return AppColors.safe;
      case 'warning': return AppColors.warning;
      case 'danger':  return AppColors.danger;
      default:        return AppColors.textHint;
    }
  }

  Color _statusBg(String? s) {
    switch (s) {
      case 'safe':    return AppColors.safeBg;
      case 'warning': return AppColors.warningBg;
      case 'danger':  return AppColors.dangerBg;
      default:        return AppColors.surfaceSub;
    }
  }

  String _statusLabel(String? s) {
    switch (s) {
      case 'safe':    return '안전';
      case 'warning': return '주의';
      case 'danger':  return '위험';
      default:        return '알 수 없음';
    }
  }

  IconData _statusIcon(String? s) {
    switch (s) {
      case 'safe':    return Icons.check_circle_rounded;
      case 'warning': return Icons.warning_rounded;
      case 'danger':  return Icons.dangerous_rounded;
      default:        return Icons.help_outline_rounded;
    }
  }

  // ── 빌드 ─────────────────────────────────────────────
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        backgroundColor: Colors.black,
        foregroundColor: Colors.white,
        title: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Container(
              width: 28, height: 28,
              decoration: BoxDecoration(
                color: AppColors.dangerBg,
                border: Border.all(color: AppColors.danger.withOpacity(0.4)),
                borderRadius: BorderRadius.circular(6),
              ),
              child: const Icon(Icons.qr_code_scanner_rounded,
                  size: 16, color: AppColors.danger),
            ),
            const SizedBox(width: 8),
            const Text('QR 피싱 방지 시스템',
              style: TextStyle(
                color: Colors.white,
                fontSize: 16,
                fontWeight: FontWeight.w600,
                letterSpacing: -0.3,
              ),
            ),
          ],
        ),
      ),
      body: Column(
        children: [
          // ── 카메라 스캔 영역 ──
          Expanded(
            flex: 5,
            child: Stack(
              children: [
                MobileScanner(
                  controller: _scannerController,
                  onDetect: (BarcodeCapture capture) {
                    if (_isProcessing || _result != null || _errorMessage != null) return;
                    final barcodes = capture.barcodes;
                    if (barcodes.isEmpty) return;
                    final value = barcodes.first.rawValue;
                    if (value == null || value.isEmpty) return;
                    _scannerController.stop();
                    _analyzeQRContent(value);
                  },
                ),

                // 스캔 프레임
                if (!_isProcessing)
                  Center(
                    child: AnimatedBuilder(
                      animation: _pulseAnim,
                      builder: (_, __) => Container(
                        width: 220, height: 220,
                        decoration: BoxDecoration(
                          border: Border.all(
                            color: Colors.white.withOpacity(_pulseAnim.value),
                            width: 2.5,
                          ),
                          borderRadius: BorderRadius.circular(16),
                        ),
                        child: Stack(children: [
                          _corner(0, 0, true,  true),
                          _corner(0, 0, true,  false),
                          _corner(0, 0, false, true),
                          _corner(0, 0, false, false),
                        ]),
                      ),
                    ),
                  ),

                // 스캔 가이드 텍스트
                if (!_isProcessing && _result == null && _errorMessage == null)
                  Positioned(
                    bottom: 24, left: 0, right: 0,
                    child: Center(
                      child: Container(
                        padding: const EdgeInsets.symmetric(
                            horizontal: 18, vertical: 10),
                        decoration: BoxDecoration(
                          color: Colors.black.withOpacity(0.55),
                          borderRadius: BorderRadius.circular(20),
                        ),
                        child: const Text(
                          'QR 코드를 네모 안에 맞춰주세요',
                          style: TextStyle(
                            color: Colors.white,
                            fontSize: 13,
                            fontWeight: FontWeight.w500,
                          ),
                        ),
                      ),
                    ),
                  ),

                // 로딩 오버레이
                if (_isProcessing)
                  Container(
                    color: Colors.black.withOpacity(0.7),
                    child: Center(
                      child: Column(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Container(
                            width: 72, height: 72,
                            decoration: BoxDecoration(
                              color: Colors.white.withOpacity(0.1),
                              shape: BoxShape.circle,
                              border: Border.all(
                                  color: Colors.white.withOpacity(0.2)),
                            ),
                            child: const Padding(
                              padding: EdgeInsets.all(18),
                              child: CircularProgressIndicator(
                                color: Colors.white,
                                strokeWidth: 2.5,
                              ),
                            ),
                          ),
                          const SizedBox(height: 20),
                          const Text('QR 내용 분석 중',
                            style: TextStyle(
                              color: Colors.white,
                              fontSize: 16,
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
              ],
            ),
          ),

          // ── 결과 패널 ──
          Expanded(
            flex: 4,
            child: Container(
              width: double.infinity,
              decoration: const BoxDecoration(
                color: AppColors.surface,
                borderRadius: BorderRadius.vertical(top: Radius.circular(24)),
              ),
              child: _errorMessage != null
                  ? _buildErrorView()
                  : _result == null
                      ? _buildGuideView()
                      : _buildResultView(),
            ),
          ),
        ],
      ),
    );
  }

  // 모서리 장식
  Widget _corner(double top, double left, bool isTop, bool isLeft) {
    return Positioned(
      top:    isTop  ? 0 : null,
      bottom: isTop  ? null : 0,
      left:   isLeft ? 0 : null,
      right:  isLeft ? null : 0,
      child: Container(
        width: 24, height: 24,
        decoration: BoxDecoration(
          border: Border(
            top:    isTop  ? const BorderSide(color: AppColors.accent, width: 3) : BorderSide.none,
            bottom: !isTop ? const BorderSide(color: AppColors.accent, width: 3) : BorderSide.none,
            left:   isLeft  ? const BorderSide(color: AppColors.accent, width: 3) : BorderSide.none,
            right:  !isLeft ? const BorderSide(color: AppColors.accent, width: 3) : BorderSide.none,
          ),
        ),
      ),
    );
  }

  // ── 가이드 뷰 ─────────────────────────────────────────
  Widget _buildGuideView() {
    return Padding(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            width: 4, height: 20,
            decoration: BoxDecoration(
              color: AppColors.accent,
              borderRadius: BorderRadius.circular(2),
            ),
          ),
          const SizedBox(height: 12),
          const Text('QR 코드를 스캔하세요',
            style: TextStyle(
              fontSize: 20,
              fontWeight: FontWeight.w700,
              color: AppColors.textPrim,
              letterSpacing: -0.5,
            ),
          ),
          const SizedBox(height: 10),
          const Text(
            'QR 코드의 내용을 분석하여\n피싱 여부와 위험도를 확인합니다.',
            style: TextStyle(
              fontSize: 14,
              color: AppColors.textSec,
              height: 1.6,
            ),
          ),
          const Spacer(),
          Row(
            children: [
              _infoChip(Icons.speed_rounded, '실시간 분석'),
            ],
          ),
        ],
      ),
    );
  }

  Widget _infoChip(IconData icon, String label) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 7),
      decoration: BoxDecoration(
        color: AppColors.surfaceSub,
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: AppColors.border),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 14, color: AppColors.accent),
          const SizedBox(width: 6),
          Text(label,
            style: const TextStyle(
              fontSize: 12,
              fontWeight: FontWeight.w500,
              color: AppColors.textSec,
            ),
          ),
        ],
      ),
    );
  }

  // ── 에러 뷰 ──────────────────────────────────────────
  Widget _buildErrorView() {
    return Padding(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(children: [
            const Icon(Icons.error_outline_rounded,
                color: AppColors.danger, size: 22),
            const SizedBox(width: 8),
            const Text('오류 발생',
              style: TextStyle(
                fontSize: 18,
                fontWeight: FontWeight.w700,
                color: AppColors.danger,
              ),
            ),
          ]),
          const SizedBox(height: 12),
          Text(_errorMessage ?? '',
            style: const TextStyle(
              fontSize: 13,
              color: AppColors.textSec,
              height: 1.6,
            ),
          ),
          const Spacer(),
          _rescanButton(),
        ],
      ),
    );
  }

  // ── 결과 뷰 ──────────────────────────────────────────
  Widget _buildResultView() {
    final status    = _result?['status'] as String?;
    final riskScore = _result?['risk_score'];
    final message   = _result?['message'] as String?;
    final reasons   = (_result?['reasons'] as List?) ?? [];
    final qrType    = _result?['qr_type'];
    final preview   = _result?['raw_content_preview'];
    final hasVtReport = _result?['vt_available'] == true &&
        _result?['vt_source'] == 'url_report';

    final color = _statusColor(status);
    final bg    = _statusBg(status);

    return SingleChildScrollView(
      padding: const EdgeInsets.fromLTRB(20, 20, 20, 16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [

          // 상태 배지 + 점수
          Row(
            children: [
              Container(
                padding: const EdgeInsets.symmetric(
                    horizontal: 14, vertical: 7),
                decoration: BoxDecoration(
                  color: bg,
                  borderRadius: BorderRadius.circular(20),
                  border: Border.all(color: color.withOpacity(0.3)),
                ),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Icon(_statusIcon(status), size: 16, color: color),
                    const SizedBox(width: 6),
                    Text(_statusLabel(status),
                      style: TextStyle(
                        fontSize: 14,
                        fontWeight: FontWeight.w700,
                        color: color,
                      ),
                    ),
                  ],
                ),
              ),
              const Spacer(),
              // 점수 카드
              Container(
                padding: const EdgeInsets.symmetric(
                    horizontal: 14, vertical: 7),
                decoration: BoxDecoration(
                  color: AppColors.surfaceSub,
                  borderRadius: BorderRadius.circular(20),
                  border: Border.all(color: AppColors.border),
                ),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const Text('위험 점수',
                      style: TextStyle(
                        fontSize: 12,
                        color: AppColors.textHint,
                        fontWeight: FontWeight.w500,
                      ),
                    ),
                    const SizedBox(width: 8),
                    Text('$riskScore',
                      style: TextStyle(
                        fontSize: 16,
                        fontWeight: FontWeight.w700,
                        color: color,
                        fontFeatures: const [FontFeature.tabularFigures()],
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),

          const SizedBox(height: 14),

          // QR 유형 + 내용 미리보기
          if (qrType != null || preview != null || hasVtReport)
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(
                color: AppColors.surfaceSub,
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: AppColors.border),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  if (qrType != null) ...[
                    Row(children: [
                      const Icon(Icons.qr_code_rounded,
                          size: 14, color: AppColors.textHint),
                      const SizedBox(width: 6),
                      Text(qrTypeLabel(qrType),
                        style: const TextStyle(
                          fontSize: 13,
                          fontWeight: FontWeight.w600,
                          color: AppColors.textSec,
                        ),
                      ),
                    ]),
                  ],
                  if (qrType != null && preview != null)
                    const SizedBox(height: 6),
                  if (preview != null) ...[
                    Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        const Icon(Icons.text_snippet_outlined,
                            size: 14, color: AppColors.textHint),
                        const SizedBox(width: 6),
                        Expanded(
                          child: Text('$preview',
                            style: const TextStyle(
                              fontSize: 12,
                              color: AppColors.textHint,
                              height: 1.5,
                            ),
                            maxLines: 2,
                            overflow: TextOverflow.ellipsis,
                          ),
                        ),
                      ],
                    ),
                  ],
                  if (hasVtReport && (qrType != null || preview != null))
                    const SizedBox(height: 6),
                  if (hasVtReport)
                    const Row(
                      children: [
                        Icon(Icons.verified_user_outlined,
                            size: 14, color: AppColors.textHint),
                        SizedBox(width: 6),
                        Text('VirusTotal 평판 검사 포함',
                          style: TextStyle(
                            fontSize: 12,
                            color: AppColors.textHint,
                          ),
                        ),
                      ],
                    ),
                ],
              ),
            ),

          const SizedBox(height: 12),

          // 안내 메시지
          if (message != null && message.isNotEmpty)
            Text(message,
              style: const TextStyle(
                fontSize: 13,
                color: AppColors.textSec,
                height: 1.6,
              ),
            ),

          // 판단 사유
          if (reasons.isNotEmpty) ...[
            const SizedBox(height: 12),
            const Text('판단 사유',
              style: TextStyle(
                fontSize: 12,
                fontWeight: FontWeight.w600,
                color: AppColors.textHint,
                letterSpacing: 0.5,
              ),
            ),
            const SizedBox(height: 6),
            ...reasons.map((r) => Padding(
              padding: const EdgeInsets.only(bottom: 5),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text('→ ',
                    style: TextStyle(
                      fontSize: 13,
                      color: AppColors.textHint,
                    ),
                  ),
                  Expanded(
                    child: Text('$r',
                      style: const TextStyle(
                        fontSize: 13,
                        color: AppColors.textSec,
                        height: 1.5,
                      ),
                    ),
                  ),
                ],
              ),
            )),
          ],

          const SizedBox(height: 16),
          _rescanButton(),
        ],
      ),
    );
  }

  // ── 다시 스캔 버튼 ────────────────────────────────────
  Widget _rescanButton() {
    return SizedBox(
      width: double.infinity,
      height: 48,
      child: FilledButton.icon(
        onPressed: _resetScan,
        icon: const Icon(Icons.qr_code_scanner_rounded, size: 18),
        label: const Text('다시 스캔하기',
          style: TextStyle(fontSize: 15, fontWeight: FontWeight.w600),
        ),
        style: FilledButton.styleFrom(
          backgroundColor: AppColors.accent,
          foregroundColor: Colors.white,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
          ),
        ),
      ),
    );
  }
}
