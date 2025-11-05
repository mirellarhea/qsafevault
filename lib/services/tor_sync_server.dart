import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';
import 'crypto_service.dart';

typedef GetVaultJson = Future<String> Function();
typedef ApplyMergedVaultJson = Future<void> Function(String mergedJson);

class TorSyncServer {
  final int port;
  final SecretKey masterKey;
  final CryptoService crypto;
  final GetVaultJson getLocalVaultJson;
  final ApplyMergedVaultJson applyMerged;

  HttpServer? _server;

  TorSyncServer({
    required this.port,
    required this.masterKey,
    required this.crypto,
    required this.getLocalVaultJson,
    required this.applyMerged,
  });

  Future<void> start() async {
    if (_server != null) return;
    _server = await HttpServer.bind(InternetAddress.loopbackIPv4, port);
    _server!.listen(_handle);
  }

  Future<void> stop() async {
    await _server?.close(force: true);
    _server = null;
  }

  Future<void> _handle(HttpRequest req) async {
    try {
      if (req.method == 'POST' && req.uri.path == '/sync') {
        final body = await req.fold<List<int>>([], (a, b) => a..addAll(b));
        final incomingJson = await crypto.decryptUtf8(masterKey, Uint8List.fromList(body));
        final localJson = await getLocalVaultJson();
        final merged = _mergeVaults(localJson, incomingJson);
        await applyMerged(merged);
        final out = await crypto.encryptUtf8(masterKey, merged);
        req.response.statusCode = 200;
        req.response.headers.set(HttpHeaders.contentTypeHeader, 'application/octet-stream');
        req.response.add(out);
        await req.response.close();
        return;
      }
      req.response.statusCode = 404;
      await req.response.close();
    } catch (_) {
      try {
        req.response.statusCode = 500;
        await req.response.close();
      } catch (_) {}
    }
  }

  String _mergeVaults(String localJson, String incomingJson) {
    List local, incoming;
    try {
      local = jsonDecode(localJson) as List;
    } catch (_) {
      local = [];
    }
    try {
      incoming = jsonDecode(incomingJson) as List;
    } catch (_) {
      incoming = [];
    }
    final map = <String, Map<String, dynamic>>{};
    for (final e in local) {
      final m = (e as Map).map((k, v) => MapEntry(k.toString(), v));
      final id = (m['id'] ?? '') as String;
      if (id.isNotEmpty) map[id] = Map<String, dynamic>.from(m);
    }
    for (final e in incoming) {
      final m = (e as Map).map((k, v) => MapEntry(k.toString(), v));
      final id = (m['id'] ?? '') as String;
      if (id.isNotEmpty) map[id] = Map<String, dynamic>.from(m);
    }
    return jsonEncode(map.values.toList());
  }
}
