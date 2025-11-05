import 'dart:async';
import 'dart:convert';
import 'dart:io';

class TorSocksClient {
  final String socksHost;
  final int socksPort;

  TorSocksClient({this.socksHost = '127.0.0.1', required this.socksPort});

  Future<List<int>> postSync({
    required String onionHost,
    int port = 5000,
    required List<int> payload,
    Duration timeout = const Duration(seconds: 30),
  }) async {
    final socket = await Socket.connect(socksHost, socksPort).timeout(timeout);
    try {
      socket.add([0x05, 0x01, 0x00]);
      await socket.flush();
      final resp1 = await _readExactly(socket, 2);
      if (resp1[0] != 0x05 || resp1[1] != 0x00) {
        throw Exception('SOCKS5 no-auth not accepted');
      }
      final hostBytes = utf8.encode(onionHost);
      final req = <int>[
        0x05,
        0x01,
        0x00,
        0x03,
        hostBytes.length,
        ...hostBytes,
        (port >> 8) & 0xFF,
        (port) & 0xFF,
      ];
      socket.add(req);
      await socket.flush();
      final head = await _readExactly(socket, 4);
      if (head[0] != 0x05 || head[1] != 0x00) {
        throw Exception('SOCKS5 connect failed (code=${head[1]})');
      }
      int addrLen;
      switch (head[3]) {
        case 0x01:
          await _readExactly(socket, 4);
          break;
        case 0x03:
          addrLen = (await _readExactly(socket, 1))[0];
          await _readExactly(socket, addrLen);
          break;
        case 0x04:
          await _readExactly(socket, 16);
          break;
        default:
          throw Exception('SOCKS5 atyp not supported');
      }
      await _readExactly(socket, 2);

      final headers = [
        'POST /sync HTTP/1.1',
        'Host: $onionHost',
        'Content-Type: application/octet-stream',
        'Content-Length: ${payload.length}',
        'Connection: close',
        '\r\n'
      ].join('\r\n');
      socket.add(utf8.encode(headers));
      socket.add(payload);
      await socket.flush();

      final bytes = await socket.fold<List<int>>([], (a, b) => a..addAll(b));
      final sep = _indexOf(bytes, ascii.encode('\r\n\r\n'));
      if (sep < 0) throw Exception('Invalid HTTP response');
      final body = bytes.sublist(sep + 4);
      return body;
    } finally {
      try {
        await socket.close();
      } catch (_) {}
    }
  }

  Future<List<int>> _readExactly(Socket s, int n) async {
    final c = Completer<List<int>>();
    final buf = <int>[];
    late StreamSubscription sub;
    sub = s.listen((data) {
      buf.addAll(data);
      if (buf.length >= n && !c.isCompleted) {
        c.complete(buf.sublist(0, n));
        sub.cancel();
      }
    }, onError: (e, st) {
      if (!c.isCompleted) c.completeError(e, st);
    }, onDone: () {
      if (!c.isCompleted) c.completeError(StateError('Socket closed'));
    });
    final out = await c.future.timeout(const Duration(seconds: 15));
    return out;
  }

  int _indexOf(List<int> list, List<int> pattern) {
    for (var i = 0; i <= list.length - pattern.length; i++) {
      var j = 0;
      while (j < pattern.length && list[i + j] == pattern[j]) {
        j++;
      }
      if (j == pattern.length) return i;
    }
    return -1;
  }
}
