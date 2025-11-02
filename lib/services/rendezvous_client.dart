import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';
import 'package:http/http.dart' as http;
import '../config/sync_config.dart';
import '../services/crypto_service.dart';

class RendezvousHttpException implements Exception {
  final int statusCode;
  final String? code;
  final String? message;
  RendezvousHttpException(this.statusCode, {this.code, this.message});
  @override
  String toString() => 'RendezvousHttpException($statusCode, code=$code, msg=$message)';
}

class RendezvousClient {
  final SyncConfig config;
  final http.Client _http;
  final CryptoService _crypto;

  late final String _baseNoSlash;

  RendezvousClient({
    SyncConfig? config,
    http.Client? httpClient,
    CryptoService? crypto,
  })  : config = config ?? SyncConfig.defaults(),
        _http = httpClient ?? http.Client(),
        _crypto = crypto ?? CryptoService() {
    final raw = this.config.baseUrl.trim();
    _baseNoSlash = raw.replaceAll(RegExp(r'/+$'), '');
  }

  Uri _u(String path, [Map<String, String>? query]) {
    final p = path.startsWith('/') ? path : '/$path';
    final uri = Uri.parse('$_baseNoSlash$p');
    if (query == null || query.isEmpty) return uri;
    return uri.replace(queryParameters: query);
  }

  void _logReq(String method, Uri uri, {Object? body}) {
  }

  void _logRes(String method, Uri uri, http.Response resp, {Object? asJson}) {
  }

  void _logInfo(String msg) {
  }

  String _toJsonString(Object o) {
    if (o is String) return o;
    return jsonEncode(o);
  }

  String _truncate(String s, [int max = 256]) {
    if (s.length <= max) return s;
    return '${s.substring(0, max)}…(${s.length})';
  }

  Map<String, dynamic> _maskCreateSession(Map<String, dynamic> obj) {
    final out = Map<String, dynamic>.from(obj);
    if (out.containsKey('pin')) out['pin'] = '******';
    return out;
  }

  Map<String, dynamic> _redactEnvelopeWrapper(Map<String, dynamic> wrapper) {
    final out = Map<String, dynamic>.from(wrapper);
    final env = Map<String, dynamic>.from((wrapper['envelope'] ?? {}) as Map<String, dynamic>);
    final ct = env['ctB64'] as String? ?? '';
    env['ctB64'] = '<redacted:${ct.length}>';
    out['envelope'] = env;
    return out;
  }

  Future<_CreateSessionResp> createSession() async {
    final uri = _u('/v1/sessions');
    _logReq('POST', uri);
    final resp = await _http
        .post(uri, headers: {'content-type': 'application/json'})
        .timeout(config.httpTimeout);
    if (resp.statusCode != 200) {
      _logRes('POST', uri, resp);
      throw RendezvousHttpException(resp.statusCode, message: 'createSession failed');
    }
    final obj = jsonDecode(resp.body) as Map<String, dynamic>;
    _logRes('POST', uri, resp, asJson: _maskCreateSession(obj));
    return _CreateSessionResp(
      sessionId: obj['sessionId'] as String,
      pin: obj['pin'] as String,
      saltB64: obj['saltB64'] as String,
      ttlSec: (obj['ttlSec'] as num).toInt(),
    );
  }

  Future<_ResolveResp> resolveByPin(String pin) async {
    final uri = _u('/v1/sessions/resolve', {'pin': '******'});
    _logReq('GET', uri);
    final realUri = _u('/v1/sessions/resolve', {'pin': pin});
    final resp = await _http.get(realUri).timeout(config.httpTimeout);
    if (resp.statusCode == 404 || resp.statusCode == 410) {
      _logRes('GET', uri, resp);
      final obj = _safeDecode(resp.body);
      throw RendezvousHttpException(resp.statusCode, code: obj?['error']?['code'], message: obj?['error']?['message']);
    }
    if (resp.statusCode != 200) {
      _logRes('GET', uri, resp);
      throw RendezvousHttpException(resp.statusCode, message: 'resolveByPin failed');
    }
    final obj = jsonDecode(resp.body) as Map<String, dynamic>;
    _logRes('GET', uri, resp, asJson: obj);
    return _ResolveResp(
      sessionId: obj['sessionId'] as String,
      saltB64: obj['saltB64'] as String,
      ttlSec: (obj['ttlSec'] as num?)?.toInt(),
    );
  }

  Future<void> putOffer({
    required String sessionId,
    required Map<String, dynamic> envelope,
  }) async {
    final uri = _u('/v1/sessions/$sessionId/offer');
    _logReq('POST', uri, body: _redactEnvelopeWrapper({'envelope': envelope}));
    final resp = await _http
        .post(uri, headers: {'content-type': 'application/json'}, body: jsonEncode({'envelope': envelope}))
        .timeout(config.httpTimeout);
    if (resp.statusCode != 200) {
      _logRes('POST', uri, resp);
      final obj = _safeDecode(resp.body);
      throw RendezvousHttpException(resp.statusCode, code: obj?['error']?['code'], message: obj?['error']?['message']);
    }
    _logRes('POST', uri, resp, asJson: {});
  }

  Future<Map<String, dynamic>?> getOffer(String sessionId) async {
    final uri = _u('/v1/sessions/$sessionId/offer');
    _logReq('GET', uri);
    final resp = await _http.get(uri).timeout(config.httpTimeout);
    if (resp.statusCode == 404 || resp.statusCode == 410) {
      _logRes('GET', uri, resp);
      return null;
    }
    if (resp.statusCode != 200) {
      _logRes('GET', uri, resp);
      final obj = _safeDecode(resp.body);
      throw RendezvousHttpException(resp.statusCode, code: obj?['error']?['code'], message: obj?['error']?['message']);
    }
    final obj = jsonDecode(resp.body) as Map<String, dynamic>;
    _logRes('GET', uri, resp, asJson: _redactEnvelopeWrapper(obj));
    return obj['envelope'] as Map<String, dynamic>?;
  }

  Future<void> putAnswer({
    required String sessionId,
    required Map<String, dynamic> envelope,
  }) async {
    final uri = _u('/v1/sessions/$sessionId/answer');
    _logReq('POST', uri, body: _redactEnvelopeWrapper({'envelope': envelope}));
    final resp = await _http
        .post(uri, headers: {'content-type': 'application/json'}, body: jsonEncode({'envelope': envelope}))
        .timeout(config.httpTimeout);
    if (resp.statusCode != 200) {
      _logRes('POST', uri, resp);
      final obj = _safeDecode(resp.body);
      throw RendezvousHttpException(resp.statusCode, code: obj?['error']?['code'], message: obj?['error']?['message']);
    }
    _logRes('POST', uri, resp, asJson: {});
  }

  Future<Map<String, dynamic>?> getAnswer(String sessionId) async {
    final uri = _u('/v1/sessions/$sessionId/answer');
    _logReq('GET', uri);
    final resp = await _http.get(uri).timeout(config.httpTimeout);
    if (resp.statusCode == 404 || resp.statusCode == 410) {
      _logRes('GET', uri, resp);
      return null;
    }
    if (resp.statusCode != 200) {
      _logRes('GET', uri, resp);
      final obj = _safeDecode(resp.body);
      throw RendezvousHttpException(resp.statusCode, code: obj?['error']?['code'], message: obj?['error']?['message']);
    }
    final obj = jsonDecode(resp.body) as Map<String, dynamic>;
    _logRes('GET', uri, resp, asJson: _redactEnvelopeWrapper(obj));
    return obj['envelope'] as Map<String, dynamic>?;
  }

  Future<void> closeSession(String sessionId) async {
    final uri = _u('/v1/sessions/$sessionId');
    _logReq('DELETE', uri);
    final resp = await _http.delete(uri).timeout(config.httpTimeout);
    _logRes('DELETE', uri, resp);
  }

  Future<Map<String, dynamic>?> pollAnswer({
    required String sessionId,
    Duration? maxWait,
  }) async {
    final deadline = DateTime.now().add(maxWait ?? config.pollMaxWait);
    _logInfo('pollAnswer start session=$sessionId maxWait=${maxWait ?? config.pollMaxWait}');
    while (DateTime.now().isBefore(deadline)) {
      final env = await getAnswer(sessionId);
      if (env != null) {
        _logInfo('pollAnswer received answer for session=$sessionId');
        return env;
      }
      await Future.delayed(jitter(config.pollInterval));
    }
    _logInfo('pollAnswer timeout session=$sessionId');
    return null;
  }

  Future<Map<String, dynamic>?> pollOffer({
    required String sessionId,
    Duration? maxWait,
  }) async {
    final deadline = DateTime.now().add(maxWait ?? config.pollMaxWait);
    _logInfo('pollOffer start session=$sessionId maxWait=${maxWait ?? config.pollMaxWait}');
    while (DateTime.now().isBefore(deadline)) {
      final env = await getOffer(sessionId);
      if (env != null) {
        _logInfo('pollOffer received offer for session=$sessionId');
        return env;
      }
      await Future.delayed(jitter(config.pollInterval));
    }
    _logInfo('pollOffer timeout session=$sessionId');
    return null;
  }

  Future<SecretKey> _derivePinKey({
    required String pin,
    required List<int> salt,
  }) {
    return _crypto.deriveKeyFromPassword(
      password: pin,
      salt: salt,
      kdf: 'argon2id',
      iterations: 2,
      memoryKb: 65536,
      parallelism: 1,
    );
  }

  Future<Map<String, dynamic>> sealPayload({
    required String sessionId,
    required String pin,
    required String saltB64,
    required Map<String, dynamic> payload,
  }) async {
    final salt = base64Decode(saltB64);
    final key = await _derivePinKey(pin: pin, salt: salt);
    final aes = AesGcm.with256bits();
    final nonce = _randomBytes(12);
    final clear = utf8.encode(jsonEncode(payload));
    final sb = await aes.encrypt(clear, secretKey: key, nonce: nonce);
    final env = {
      'v': 1,
      'sessionId': sessionId,
      'nonceB64': base64Encode(sb.nonce),
      'ctB64': base64Encode(Uint8List.fromList(sb.cipherText + sb.mac.bytes)),
    };
    _logInfo('sealed payload for session=$sessionId type=${payload['type']} ctLen=${(env['ctB64'] as String).length}');
    return env;
  }

  Future<Map<String, dynamic>> openEnvelope({
    required Map<String, dynamic> envelope,
    required String pin,
    required String saltB64,
  }) async {
    final nonce = base64Decode(envelope['nonceB64'] as String);
    final ctAll = base64Decode(envelope['ctB64'] as String);
    final macLen = 16;
    if (ctAll.length < macLen) {
      throw Exception('Invalid envelope');
    }
    final cipherText = ctAll.sublist(0, ctAll.length - macLen);
    final mac = Mac(ctAll.sublist(ctAll.length - macLen));
    final aes = AesGcm.with256bits();
    final key = await _derivePinKey(pin: pin, salt: base64Decode(saltB64));
    final clear = await aes.decrypt(SecretBox(cipherText, nonce: nonce, mac: mac), secretKey: key);
    final obj = jsonDecode(utf8.decode(clear)) as Map<String, dynamic>;
    _logInfo('opened envelope type=${obj['type']} sdpLen=${(obj['sdp'] as String?)?.length ?? 0}');
    return obj;
  }

  Uint8List _randomBytes(int n) {
    final r = Random.secure();
    return Uint8List.fromList(List<int>.generate(n, (_) => r.nextInt(256)));
  }

  Map<String, dynamic>? _safeDecode(String body) {
    try {
      return jsonDecode(body) as Map<String, dynamic>;
    } catch (_) {
      return null;
    }
  }
}

class _CreateSessionResp {
  final String sessionId;
  final String pin;
  final String saltB64;
  final int ttlSec;
  _CreateSessionResp({required this.sessionId, required this.pin, required this.saltB64, required this.ttlSec});
}

class _ResolveResp {
  final String sessionId;
  final String saltB64;
  final int? ttlSec;
  _ResolveResp({required this.sessionId, required this.saltB64, this.ttlSec});
}
