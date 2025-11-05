import 'dart:math';

class SyncConfig {
  final String baseUrl;
  final Duration httpTimeout;
  final Duration pollInterval;
  final Duration pollMaxWait;
  final Duration backoffMax;
  final List<String> turnUrls;
  final String? turnUsername;
  final String? turnCredential;
  final bool turnForceRelay;

  const SyncConfig({
    required this.baseUrl,
    this.httpTimeout = const Duration(seconds: 8),
    this.pollInterval = const Duration(milliseconds: 800),
    this.pollMaxWait = const Duration(seconds: 180),
    this.backoffMax = const Duration(seconds: 3),
    this.turnUrls = const [],
    this.turnUsername,
    this.turnCredential,
    this.turnForceRelay = false,
  });

  static SyncConfig defaults() {
    final base = const String.fromEnvironment(
      'QSV_SYNC_BASEURL',
      defaultValue: 'https://qsafevault-server.vercel.app',
    );
    final turnUrls = const String.fromEnvironment('QSV_TURN_URLS', defaultValue: '')
        .split(',')
        .map((s) => s.trim())
        .where((s) => s.isNotEmpty)
        .toList();
    final turnUser = const String.fromEnvironment('QSV_TURN_USERNAME', defaultValue: '').trim();
    final turnCred = const String.fromEnvironment('QSV_TURN_CREDENTIAL', defaultValue: '').trim();
    final forceRelayRaw = const String.fromEnvironment('QSV_TURN_FORCE_RELAY', defaultValue: 'false');
    final forceRelay = forceRelayRaw == '1' || forceRelayRaw.toLowerCase() == 'true';

    return SyncConfig(
      baseUrl: base,
      turnUrls: turnUrls,
      turnUsername: turnUser.isEmpty ? null : turnUser,
      turnCredential: turnCred.isEmpty ? null : turnCred,
      turnForceRelay: forceRelay,
    );
  }
}

Duration jitter(Duration base, {int msJitter = 150}) {
  final r = Random.secure().nextInt(msJitter * 2) - msJitter;
  final t = base + Duration(milliseconds: r);
  return t.isNegative ? Duration.zero : t;
}
