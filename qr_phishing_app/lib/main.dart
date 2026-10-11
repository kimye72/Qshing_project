import 'dart:async';
import 'dart:convert';

import 'package:flutter/foundation.dart';
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


  // ── [디버그 전용] 카메라 없이 화면 미리보기 (작업 끝나면 삭제) ──
  void _debugPreview(String kind) {
    if (!kDebugMode) return;
    setState(() {
      _isProcessing = false;
      _result = null;
      _errorMessage = null;
      switch (kind) {
        case 'loading':
          _isProcessing = true;
          break;
        case 'error':
          _errorMessage = '서버 응답 시간이 초과되었습니다.\n잠시 후 다시 시도해주세요.';
          break;
        case 'safe':
          _result = {
            'qr_type': 'url',
            'raw_content_preview': 'https://www.google.com/',
            'risk_score': 5,
            'status': 'safe',
            'message': '안전한 URL로 판단됩니다.',
            'reasons': ['특별한 위험 요소가 발견되지 않았습니다.'],
          };
          break;
        case 'warning':
          _result = {
            'qr_type': 'phone_text',
            'raw_content_preview': '고객센터 010-****-5678로 인증번호를 알려주세요',
            'risk_score': 55,
            'status': 'warning',
            'message': '주의가 필요한 QR입니다. 내용을 확인한 뒤 신중히 진행하세요.',
            'reasons': [
              '전화번호가 포함되어 있습니다.',
              '인증번호 문구가 포함되어 있습니다.',
              '고객센터 문구가 포함되어 있습니다.',
            ],
          };
          break;
        case 'danger':
          _result = {
            'qr_type': 'url',
            'raw_content_preview': 'http://192.168.0.1/login-bank-update',
            'risk_score': 85,
            'status': 'danger',
            'message': '위험한 QR입니다. 접속하지 마세요.',
            'reasons': [
              'HTTP를 사용합니다.',
              'IP 주소가 직접 사용되었습니다.',
              '의심 키워드 포함: login',
              '의심 키워드 포함: bank',
            ],
            'vt_available': true,
            'vt_source': 'url_report',
          };
          break;
      }
    });
  }

  static const Color _ink = Color(0xFF0F172A);

  // ── 빌드 ─────────────────────────────────────────────
  @override
  Widget build(BuildContext context) {
    final showResult = _result != null;
    final showError = _errorMessage != null;
    final scanning = !showResult && !showError;

    return Scaffold(
      backgroundColor: _ink,
      body: Stack(
        fit: StackFit.expand,
        children: [
          // 카메라 (항상 유지: 스캔 로직 그대로)
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

          if (scanning) _buildScanLayer(),
          if (_isProcessing) _buildLoadingLayer(),
          if (showResult) _buildResultScreen(),
          if (showError) _buildErrorScreen(),

          // 디버그 미리보기 메뉴
          if (kDebugMode)
            SafeArea(
              child: Align(
                alignment: Alignment.topRight,
                child: Padding(
                  padding: const EdgeInsets.all(8),
                  child: PopupMenuButton<String>(
                    icon: const Icon(Icons.bug_report_rounded),
                    iconColor: scanning ? Colors.white : AppColors.textHint,
                    tooltip: '화면 미리보기',
                    onSelected: (v) => v == 'reset' ? _resetScan() : _debugPreview(v),
                    itemBuilder: (_) => const [
                      PopupMenuItem(value: 'loading', child: Text('로딩 화면')),
                      PopupMenuItem(value: 'safe', child: Text('결과: 안전')),
                      PopupMenuItem(value: 'warning', child: Text('결과: 주의')),
                      PopupMenuItem(value: 'danger', child: Text('결과: 위험')),
                      PopupMenuItem(value: 'error', child: Text('오류 화면')),
                      PopupMenuItem(value: 'reset', child: Text('스캔 화면으로')),
                    ],
                  ),
                ),
              ),
            ),
        ],
      ),
    );
  }

  // ── 스캔 화면 ─────────────────────────────────────────
  Widget _buildScanLayer() {
    return Stack(
      fit: StackFit.expand,
      children: [
        LayoutBuilder(builder: (context, c) {
          final rect = Rect.fromCenter(
            center: Offset(c.maxWidth / 2, c.maxHeight * 0.36),
            width: 250, height: 250,
          );
          return Stack(children: [
            Positioned.fill(
              child: IgnorePointer(child: CustomPaint(painter: _ScanMaskPainter(rect))),
            ),
            Positioned.fromRect(
              rect: rect,
              child: IgnorePointer(
                child: AnimatedBuilder(
                  animation: _pulseAnim,
                  builder: (_, __) => Container(
                    decoration: BoxDecoration(
                      border: Border.all(
                        color: Colors.white.withOpacity(0.45 + 0.45 * _pulseAnim.value),
                        width: 2,
                      ),
                      borderRadius: BorderRadius.circular(28),
                    ),
                  ),
                ),
              ),
            ),
          ]);
        }),

                // 상단 로고 (좌측 상단 고정)
        Positioned(
          top: 0, left: 0, right: 0,
          child: SafeArea(
            child: Padding(
              padding: const EdgeInsets.fromLTRB(20, 14, 20, 0),
              child: Row(children: [
                Container(
                  width: 34, height: 34,
                  decoration: BoxDecoration(
                    color: Colors.white.withOpacity(0.14),
                    borderRadius: BorderRadius.circular(10),
                  ),
                  child: const Icon(Icons.shield_outlined, size: 20, color: Colors.white),
                ),
                const SizedBox(width: 10),
                const Text('QR 피싱 방지',
                  style: TextStyle(
                    color: Colors.white, fontSize: 17,
                    fontWeight: FontWeight.w700, letterSpacing: -0.3,
                  ),
                ),
              ]),
            ),
          ),
        ),

        // 하단 안내 패널
        Positioned(left: 0, right: 0, bottom: 0, child: _buildGuidePanel()),
      ],
    );
  }

  Widget _buildGuidePanel() {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.fromLTRB(24, 24, 24, 20),
      decoration: const BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.vertical(top: Radius.circular(28)),
      ),
      child: SafeArea(
        top: false,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(children: [
              Container(
                width: 44, height: 44,
                decoration: BoxDecoration(
                  color: AppColors.accentBg,
                  borderRadius: BorderRadius.circular(14),
                ),
                child: const Icon(Icons.verified_user_rounded,
                    color: AppColors.accent, size: 24),
              ),
              const SizedBox(width: 14),
              const Expanded(
                child: Text('QR 코드를 네모 안에 맞춰주세요',
                  style: TextStyle(
                    fontSize: 18, fontWeight: FontWeight.w800,
                    color: AppColors.textPrim, letterSpacing: -0.4,
                  ),
                ),
              ),
            ]),
            const SizedBox(height: 12),
            const Text(
              'QR을 자동으로 열지 않고, 먼저 위험도를 분석합니다.',
              style: TextStyle(fontSize: 14, color: AppColors.textSec, height: 1.5),
            ),
            const SizedBox(height: 16),
            Wrap(spacing: 8, runSpacing: 8, children: [
              _infoChip(Icons.link_rounded, 'URL'),
              _infoChip(Icons.phone_outlined, '전화번호'),
              _infoChip(Icons.sms_outlined, '문자'),
              _infoChip(Icons.mail_outline_rounded, '이메일'),
              _infoChip(Icons.wifi_rounded, 'Wi-Fi'),
            ]),
          ],
        ),
      ),
    );
  }

  Widget _infoChip(IconData icon, String label) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 7),
      decoration: BoxDecoration(
        color: AppColors.surfaceSub,
        borderRadius: BorderRadius.circular(20),
      ),
      child: Row(mainAxisSize: MainAxisSize.min, children: [
        Icon(icon, size: 14, color: AppColors.accent),
        const SizedBox(width: 6),
        Text(label,
          style: const TextStyle(
            fontSize: 12, fontWeight: FontWeight.w600, color: AppColors.textSec,
          ),
        ),
      ]),
    );
  }

  // ── 로딩 화면 ─────────────────────────────────────────
  Widget _buildLoadingLayer() {
    return Container(
      color: _ink.withOpacity(0.88),
      child: Center(
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          const SizedBox(
            width: 64, height: 64,
            child: CircularProgressIndicator(
              color: Colors.white, strokeWidth: 3, strokeCap: StrokeCap.round,
            ),
          ),
          const SizedBox(height: 28),
          const Text('QR 내용 분석 중...',
            style: TextStyle(
              color: Colors.white, fontSize: 20,
              fontWeight: FontWeight.w700, letterSpacing: -0.4,
            ),
          ),
          const SizedBox(height: 10),
          Text('URL, 전화번호, 문자, Wi-Fi 정보를\n확인하고 있어요.',
            textAlign: TextAlign.center,
            style: TextStyle(
              color: Colors.white.withOpacity(0.7), fontSize: 14, height: 1.5,
            ),
          ),
        ]),
      ),
    );
  }

  // ── 결과 화면 ─────────────────────────────────────────
  Widget _buildResultScreen() {
    final status    = _result?['status'] as String?;
    final rawScore  = _result?['risk_score'];
    final message   = _result?['message'] as String?;
    final reasons   = (_result?['reasons'] as List?) ?? [];
    final qrType    = _result?['qr_type'];
    final preview   = _result?['raw_content_preview'];
    final hasVtReport = _result?['vt_available'] == true &&
        _result?['vt_source'] == 'url_report';
    final score = (rawScore is num ? rawScore.toDouble() : 0.0).clamp(0.0, 100.0);
    final color = _statusColor(status);

    return Container(
      color: AppColors.bg,
      child: Column(children: [
        Expanded(
          child: SingleChildScrollView(
            child: Column(children: [
              // 상단 요약 영역
              Container(
                width: double.infinity,
                decoration: BoxDecoration(
                  gradient: LinearGradient(
                    begin: Alignment.topCenter,
                    end: Alignment.bottomCenter,
                    colors: [color.withOpacity(0.2), AppColors.bg],
                  ),
                ),
                child: SafeArea(
                  bottom: false,
                  child: Padding(
                    padding: const EdgeInsets.fromLTRB(24, 36, 24, 20),
                    child: Column(children: [
                      TweenAnimationBuilder<double>(
                        tween: Tween(begin: 0, end: score / 100),
                        duration: const Duration(milliseconds: 900),
                        curve: Curves.easeOutCubic,
                        builder: (_, v, __) => SizedBox(
                          width: 156, height: 156,
                          child: Stack(alignment: Alignment.center, children: [
                            SizedBox.expand(
                              child: CircularProgressIndicator(
                                value: v, strokeWidth: 11,
                                strokeCap: StrokeCap.round,
                                backgroundColor: color.withOpacity(0.16),
                                color: color,
                              ),
                            ),
                            Column(mainAxisSize: MainAxisSize.min, children: [
                              Text('${score.round()}',
                                style: TextStyle(
                                  fontSize: 48, fontWeight: FontWeight.w800,
                                  color: color, height: 1,
                                  fontFeatures: const [FontFeature.tabularFigures()],
                                ),
                              ),
                              const SizedBox(height: 4),
                              const Text('위험 점수',
                                style: TextStyle(
                                  fontSize: 12, color: AppColors.textHint,
                                  fontWeight: FontWeight.w600,
                                ),
                              ),
                            ]),
                          ]),
                        ),
                      ),
                      const SizedBox(height: 22),
                      Container(
                        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                        decoration: BoxDecoration(
                          color: color, borderRadius: BorderRadius.circular(24),
                        ),
                        child: Row(mainAxisSize: MainAxisSize.min, children: [
                          Icon(_statusIcon(status), size: 18, color: Colors.white),
                          const SizedBox(width: 6),
                          Text(_statusLabel(status),
                            style: const TextStyle(
                              fontSize: 16, fontWeight: FontWeight.w800, color: Colors.white,
                            ),
                          ),
                        ]),
                      ),
                      if (message != null && message.isNotEmpty) ...[
                        const SizedBox(height: 14),
                        Text(message,
                          textAlign: TextAlign.center,
                          style: const TextStyle(
                            fontSize: 15, color: AppColors.textPrim,
                            fontWeight: FontWeight.w600, height: 1.5,
                          ),
                        ),
                      ],
                    ]),
                  ),
                ),
              ),

              // 스캔 정보 카드
              if (qrType != null || preview != null)
                _card(
                  title: '스캔 정보',
                  icon: Icons.qr_code_2_rounded,
                  child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                    if (qrType != null) _infoRow('유형', qrTypeLabel(qrType)),
                    if (preview != null) _infoRow('내용', '$preview'),
                    if (hasVtReport)
                      const Padding(
                        padding: EdgeInsets.only(top: 4),
                        child: Row(children: [
                          Icon(Icons.verified_user_outlined,
                              size: 14, color: AppColors.textHint),
                          SizedBox(width: 6),
                          Text('VirusTotal 평판 검사 포함',
                            style: TextStyle(fontSize: 12, color: AppColors.textHint),
                          ),
                        ]),
                      ),
                  ]),
                ),

              // 판단 사유 카드
              if (reasons.isNotEmpty)
                _card(
                  title: '판단 사유',
                  icon: Icons.fact_check_outlined,
                  child: Column(
                    children: reasons.map((r) => Padding(
                      padding: const EdgeInsets.only(bottom: 10),
                      child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
                        Padding(
                          padding: const EdgeInsets.only(top: 6, right: 10),
                          child: Container(
                            width: 7, height: 7,
                            decoration: BoxDecoration(color: color, shape: BoxShape.circle),
                          ),
                        ),
                        Expanded(
                          child: Text('$r',
                            style: const TextStyle(
                              fontSize: 14, color: AppColors.textSec, height: 1.5,
                            ),
                          ),
                        ),
                      ]),
                    )).toList(),
                  ),
                ),
              const SizedBox(height: 16),
            ]),
          ),
        ),
        _bottomAction(),
      ]),
    );
  }

  Widget _card({required String title, required IconData icon, required Widget child}) {
    return Container(
      width: double.infinity,
      margin: const EdgeInsets.fromLTRB(20, 0, 20, 12),
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(18),
        border: Border.all(color: AppColors.border),
      ),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Row(children: [
          Icon(icon, size: 18, color: AppColors.accent),
          const SizedBox(width: 8),
          Text(title,
            style: const TextStyle(
              fontSize: 15, fontWeight: FontWeight.w700, color: AppColors.textPrim,
            ),
          ),
        ]),
        const SizedBox(height: 14),
        child,
      ]),
    );
  }

  Widget _infoRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
        SizedBox(
          width: 44,
          child: Text(label,
            style: const TextStyle(
              fontSize: 13, color: AppColors.textHint, fontWeight: FontWeight.w600,
            ),
          ),
        ),
        Expanded(
          child: Text(value,
            maxLines: 3, overflow: TextOverflow.ellipsis,
            style: const TextStyle(
              fontSize: 14, color: AppColors.textPrim,
              fontWeight: FontWeight.w600, height: 1.5,
            ),
          ),
        ),
      ]),
    );
  }

  // ── 오류 화면 ─────────────────────────────────────────
  Widget _buildErrorScreen() {
    return Container(
      color: AppColors.bg,
      child: Column(children: [
        Expanded(
          child: SafeArea(
            bottom: false,
            child: Center(
              child: Padding(
                padding: const EdgeInsets.symmetric(horizontal: 32),
                child: Column(mainAxisSize: MainAxisSize.min, children: [
                  Container(
                    width: 88, height: 88,
                    decoration: const BoxDecoration(
                      color: AppColors.dangerBg, shape: BoxShape.circle,
                    ),
                    child: const Icon(Icons.cloud_off_rounded,
                        size: 40, color: AppColors.danger),
                  ),
                  const SizedBox(height: 24),
                  const Text('분석 중 문제가 발생했습니다',
                    style: TextStyle(
                      fontSize: 20, fontWeight: FontWeight.w800,
                      color: AppColors.textPrim, letterSpacing: -0.4,
                    ),
                  ),
                  const SizedBox(height: 12),
                  Text(_errorMessage ?? '',
                    textAlign: TextAlign.center,
                    style: const TextStyle(
                      fontSize: 14, color: AppColors.textSec, height: 1.6,
                    ),
                  ),
                  const SizedBox(height: 6),
                  const Text('네트워크 연결을 확인한 뒤 다시 시도해 주세요.',
                    textAlign: TextAlign.center,
                    style: TextStyle(fontSize: 13, color: AppColors.textHint, height: 1.6),
                  ),
                ]),
              ),
            ),
          ),
        ),
        _bottomAction(),
      ]),
    );
  }

  // ── 하단 고정 버튼 ────────────────────────────────────
  Widget _bottomAction() {
    return Container(
      padding: const EdgeInsets.fromLTRB(20, 12, 20, 12),
      decoration: const BoxDecoration(
        color: AppColors.surface,
        border: Border(top: BorderSide(color: AppColors.border)),
      ),
      child: SafeArea(top: false, child: _rescanButton()),
    );
  }

  Widget _rescanButton() {
    return SizedBox(
      width: double.infinity,
      height: 56,
      child: FilledButton.icon(
        onPressed: _resetScan,
        icon: const Icon(Icons.qr_code_scanner_rounded, size: 20),
        label: const Text('다시 스캔하기',
          style: TextStyle(fontSize: 16, fontWeight: FontWeight.w700),
        ),
        style: FilledButton.styleFrom(
          backgroundColor: _ink,
          foregroundColor: Colors.white,
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        ),
      ),
    );
  }
}

// 스캔 영역만 밝게 남기는 어두운 마스크
class _ScanMaskPainter extends CustomPainter {
  final Rect hole;
  _ScanMaskPainter(this.hole);

  @override
  void paint(Canvas canvas, Size size) {
    final path = Path()
      ..fillType = PathFillType.evenOdd
      ..addRect(Offset.zero & size)
      ..addRRect(RRect.fromRectAndRadius(hole, const Radius.circular(28)));
    canvas.drawPath(path, Paint()..color = Colors.black.withOpacity(0.55));
  }

  @override
  bool shouldRepaint(_ScanMaskPainter old) => old.hole != hole;
}