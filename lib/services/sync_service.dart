import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';
import 'dart:io';
import 'package:cryptography/cryptography.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:flutter_webrtc/flutter_webrtc.dart';
import 'package:meta/meta.dart';
import '../config/sync_config.dart';
import 'rendezvous_client.dart';
import 'package:qsafevault/services/secure_storage.dart';
import 'app_logger.dart';

@immutable
class PinSession {
  final String sessionId;
  final String pin;
  final String saltB64;
  final int ttlSec;
  const PinSession({required this.sessionId, required this.pin, required this.saltB64, required this.ttlSec});
}

@immutable
class JoinOffer {
  final String sessionId;
  final String saltB64;
  final Map<String, String> offer;
  const JoinOffer({required this.sessionId, required this.saltB64, required this.offer});
}

class SyncService {
  Map<String, dynamic> _buildRtcConfig() {
    final cfg = SyncConfig.defaults();
    final iceServers = <Map<String, dynamic>>[
      {
        'urls': [
          'stun:stun.l.google.com:19302',
          'stun:global.stun.twilio.com:3478',
        ]
      },
    ];
    if (cfg.turnUrls.isNotEmpty &&
        (cfg.turnUsername?.isNotEmpty ?? false) &&
        (cfg.turnCredential?.isNotEmpty ?? false)) {
      iceServers.add({
        'urls': cfg.turnUrls,
        'username': cfg.turnUsername,
        'credential': cfg.turnCredential,
      });
    }
    return <String, dynamic>{
      'iceServers': iceServers,
      'iceTransportPolicy': cfg.turnForceRelay ? 'relay' : 'all',
      'sdpSemantics': 'unified-plan',
      'bundlePolicy': 'max-bundle',
      'rtcpMuxPolicy': 'require',
      'iceCandidatePoolSize': 4,
    };
  }

  static const _kDevicePrivKey = 'device.ed25519.priv';
  static const _kDevicePubKey = 'device.ed25519.pub';
  static const _kTrustedPeers = 'sync.trusted.pubkeys';

  final SecureStorage _secure = SecureStorage();
  final RendezvousClient _rv = RendezvousClient(config: SyncConfig.defaults());

  SimpleKeyPair? _deviceKeyPair;
  String? _devicePubKeyB64;

  RTCPeerConnection? _pc;
  RTCDataChannel? _dc;
  StreamController<SyncEvent>? _events;
  SyncStatus status = SyncStatus.idle;

  Set<String> _trustedPeers = {};

  String? _remotePubKeyB64;
  bool _channelOpen = false;

  void _logSync(String msg) {
    try {
      final line = '[webrtc] ${DateTime.now().toIso8601String()} $msg';
      AppLogger.instance.write(line);
    } catch (_) {}
  }

  Stream<SyncEvent>? get events => _events?.stream;

  Future<void> init() async {
    if (_events != null) return;
    _events = StreamController<SyncEvent>.broadcast();
    await _loadOrCreateDeviceKeys();
    await _loadTrustedPeers();
  }

  Future<String> getDevicePublicKeyBase64() async {
    await init();
    return _devicePubKeyB64!;
  }

  Future<void> addTrustedPeer(String peerPubKeyBase64) async {
    await init();
    _trustedPeers.add(peerPubKeyBase64);
    await _persistTrustedPeers();
    _events?.add(SyncEvent.trustedPeersUpdated(_trustedPeers.toList()));
  }

  Future<List<String>> getTrustedPeers() async {
    await init();
    return _trustedPeers.toList();
  }

  Future<Map<String, String>> createOffer() async {
    await init();
    await _ensurePcAndChannel(isOfferer: true);

    status = SyncStatus.signaling;
    final offer = await _pc!.createOffer({'offerToReceiveAudio': false, 'offerToReceiveVideo': false});
    await _pc!.setLocalDescription(offer);

    await _awaitIceGatheringComplete();
    final local = await _pc!.getLocalDescription();
    final payload = <String, String>{
      'type': local?.type ?? 'offer',
      'sdp': local?.sdp ?? '',
    };
    _events?.add(SyncEvent.localDescriptionReady(payload['sdp']!, payload['type']!));
    return payload;
  }

  Future<void> setRemoteAnswer(Map<String, String> answer) async {
    if (_pc == null) throw StateError('PeerConnection not initialized');
    final desc = RTCSessionDescription(answer['sdp']!, answer['type']!);
    await _pc!.setRemoteDescription(desc);
  }

  Future<Map<String, String>> createAnswerForRemoteOffer(Map<String, String> remoteOffer) async {
    await init();
    await _ensurePcAndChannel(isOfferer: false);

    status = SyncStatus.signaling;
    final offer = RTCSessionDescription(remoteOffer['sdp']!, remoteOffer['type']!);
    await _pc!.setRemoteDescription(offer);

    final answer = await _pc!.createAnswer({'offerToReceiveAudio': false, 'offerToReceiveVideo': false});
    await _pc!.setLocalDescription(answer);

    await _awaitIceGatheringComplete();
    final local = await _pc!.getLocalDescription();
    final payload = <String, String>{
      'type': local?.type ?? 'answer',
      'sdp': local?.sdp ?? '',
    };
    _events?.add(SyncEvent.localDescriptionReady(payload['sdp']!, payload['type']!));
    return payload;
  }


  Future<void> sendHello() async {
    _ensureChannelOpen();
    final msg = {
      'type': 'hello',
      'pubKey': _devicePubKeyB64,
      'version': 1,
    };
    _dc!.send(RTCDataChannelMessage(jsonEncode(msg)));
  }

  Future<SyncManifest> sendManifest(String vaultJson) async {
    _ensureChannelOpen();
    final m = SyncManifest.fromVaultJson(vaultJson);
    final msg = {
      'type': 'manifest',
      'timestamp': m.timestampMs,
      'hash': m.hashBase64,
      'version': m.version,
    };
    _dc!.send(RTCDataChannelMessage(jsonEncode(msg)));
    return m;
  }

  Future<void> requestVault() async {
    _ensureChannelOpen();
    _dc!.send(RTCDataChannelMessage(jsonEncode({'type': 'request_vault'})));
  }

  Future<void> sendVaultData(String vaultJson) async {
    _ensureChannelOpen();
    _dc!.send(RTCDataChannelMessage(jsonEncode({
      'type': 'vault',
      'json': vaultJson,
    })));
    _events?.add(const DataSentEvent());
  }

  Future<void> stop() async {
    try {
      await _dc?.close();
    } catch (_) {}
    try {
      await _pc?.close();
    } catch (_) {}
    _dc = null;
    _pc = null;
    _channelOpen = false;
    _remotePubKeyB64 = null;
    status = SyncStatus.idle;
    await _events?.close();
    _events = null;
  }


  Future<void> _ensurePcAndChannel({required bool isOfferer}) async {
    if (_pc != null) return;
    _pc = await createPeerConnection(_buildRtcConfig());
    _logSync('PeerConnection created (offerer=$isOfferer)');

    _pc!.onIceCandidate = (RTCIceCandidate c) {
      final cand = c.candidate ?? '';
      String type = '?';
      final m = RegExp(r'typ\s(\w+)').firstMatch(cand);
      if (m != null) type = m.group(1)!;
      _logSync('ICE cand type=$type');
    };

    if (isOfferer) {
      final init = RTCDataChannelInit()..ordered = true;
      _dc = await _pc!.createDataChannel('sync', init);
      _logSync('DataChannel created (label=${_dc?.label})');
      _wireDataChannel(_dc!);
    } else {
      _pc!.onDataChannel = (ch) {
        _dc = ch;
        _logSync('DataChannel received (label=${_dc?.label})');
        _wireDataChannel(ch);
      };
    }

    _pc!.onIceConnectionState = (state) async {
      _logSync('ICE state: $state');
      if (state == RTCIceConnectionState.RTCIceConnectionStateFailed) {
        try {
          await _pc?.restartIce();
          _logSync('ICE restart invoked');
          _events?.add(const ErrorEvent('ICE connection failed; attempting restart'));
        } catch (_) {}
      }
    };
    _pc!.onConnectionState = (state) {
      _logSync('PC state: $state');
      if (state == RTCPeerConnectionState.RTCPeerConnectionStateFailed ||
          state == RTCPeerConnectionState.RTCPeerConnectionStateDisconnected) {
        _events?.add(const ErrorEvent('Connection lost'));
      }
    };
  }

  void _wireDataChannel(RTCDataChannel ch) {
    ch.onDataChannelState = (s) async {
      _logSync('DC state: $s');
      if (s == RTCDataChannelState.RTCDataChannelOpen) {
        _channelOpen = true;
        status = SyncStatus.connected;
        _events?.add(const HandshakeCompleteEvent());
        await sendHello();
      }
    };
    ch.onMessage = (RTCDataChannelMessage m) async {
      _logSync('DC msg: ${m.isBinary ? 'binary' : 'text'} len=${m.text.length}');
      final obj = jsonDecode(m.text);
      switch (obj['type']) {
        case 'hello':
          _remotePubKeyB64 = obj['pubKey'] as String?;
          if (_remotePubKeyB64 == null) {
            _events?.add(const ErrorEvent('Missing peer public key'));
            await stop();
            return;
          }
          if (!_trustedPeers.contains(_remotePubKeyB64)) {
            _events?.add(UntrustedPeerEvent(_remotePubKeyB64!));
            return;
          }
          _events?.add(PeerAuthenticatedEvent(_remotePubKeyB64!));
          break;

        case 'manifest':
          final manifest = SyncManifest(
            version: (obj['version'] ?? 1) as int,
            timestampMs: (obj['timestamp'] as num).toInt(),
            hashBase64: obj['hash'] as String,
          );
          _events?.add(ManifestReceivedEvent(manifest));
          break;

        case 'request_vault':
          _events?.add(const VaultRequestedEvent());
          break;

        case 'vault':
          final vaultJson = obj['json'] as String;
          _events?.add(const DataReceivedEvent());
          _events?.add(VaultReceivedEvent(vaultJson));
          break;

        case 'ack':
          break;

        default:
          _events?.add(ErrorEvent('Unknown message type: ${obj['type']}'));
      }
    };
  }

  Future<void> _awaitIceGatheringComplete() async {
    final c = Completer<void>();
    if (_pc == null) {
      c.complete();
      return c.future;
    }
    if (_pc!.iceGatheringState == RTCIceGatheringState.RTCIceGatheringStateComplete) {
      c.complete();
      return c.future;
    }
    _pc!.onIceGatheringState = (s) {
      _logSync('ICE gathering: $s');
      if (s == RTCIceGatheringState.RTCIceGatheringStateComplete && !c.isCompleted) {
        c.complete();
      }
    };
    return c.future.timeout(const Duration(seconds: 20), onTimeout: () {
      if (!c.isCompleted) c.complete();
    });
  }

  void _ensureChannelOpen() {
    if (_dc == null || !_channelOpen) {
      throw StateError('Data channel is not open');
    }
  }


  Future<void> _loadOrCreateDeviceKeys() async {
    final existingPriv = await _secure.read(_kDevicePrivKey);
    final existingPub = await _secure.read(_kDevicePubKey);

    if (existingPriv != null && existingPub != null) {
      _deviceKeyPair = SimpleKeyPairData(
        Uint8List.fromList(existingPriv),
        publicKey: SimplePublicKey(existingPub, type: KeyPairType.ed25519),
        type: KeyPairType.ed25519,
      );
      _devicePubKeyB64 = base64Encode(existingPub);
      return;
    }

    final alg = Ed25519();
    final kp = await alg.newKeyPair();
    final pub = await kp.extractPublicKey();
    final privBytes = await kp.extractPrivateKeyBytes();
    final pubBytes = pub.bytes;

    await _secure.write(_kDevicePrivKey, privBytes);
    await _secure.write(_kDevicePubKey, pubBytes);

    _deviceKeyPair = kp;
    _devicePubKeyB64 = base64Encode(pubBytes);
  }

  Future<void> _loadTrustedPeers() async {
    final raw = await _secure.read(_kTrustedPeers);
    if (raw == null || raw.isEmpty) {
      _trustedPeers = {};
      return;
    }
    try {
      final list = jsonDecode(utf8.decode(raw)) as List<dynamic>;
      _trustedPeers = list.map((e) => e as String).toSet();
    } catch (_) {
      _trustedPeers = {};
    }
  }

  Future<void> _persistTrustedPeers() async {
    final bytes = utf8.encode(jsonEncode(_trustedPeers.toList()));
    await _secure.write(_kTrustedPeers, bytes);
  }

  Future<PinSession> createPinPairingSession() async {
    final s = await _rv.createSession();
    return PinSession(sessionId: s.sessionId, pin: s.pin, saltB64: s.saltB64, ttlSec: s.ttlSec);
  }

  Future<void> hostPublishOffer({
    required String sessionId,
    required String pin,
    required String saltB64,
    required Map<String, String> offer,
  }) async {
    final env = await _rv.sealPayload(sessionId: sessionId, pin: pin, saltB64: saltB64, payload: offer);
    await _rv.putOffer(sessionId: sessionId, envelope: env);
  }

  Future<void> hostWaitForAnswer({
    required String sessionId,
    required String pin,
    required String saltB64,
    Duration? maxWait,
  }) async {
    final env = await _rv.pollAnswer(
      sessionId: sessionId,
      maxWait: maxWait ?? SyncConfig.defaults().pollMaxWait,
    );
    if (env == null) throw Exception('Answer not received before timeout');
    final payload = await _rv.openEnvelope(envelope: env, pin: pin, saltB64: saltB64);
    final answer = {
      'type': payload['type'] as String,
      'sdp': payload['sdp'] as String,
    };
    await setRemoteAnswer(answer);
    try { await _rv.closeSession(sessionId); } catch (_) {}
  }

  Future<JoinOffer> joinFetchOfferByPin(String pin) async {
    final r = await _rv.resolveByPin(pin);
    final int waitSec = (r.ttlSec ?? 30);
    final int bounded = waitSec > 30 ? 30 : (waitSec < 1 ? 1 : waitSec);
    final env = await _rv.pollOffer(
      sessionId: r.sessionId,
      maxWait: Duration(seconds: bounded),
    );
    if (env == null) throw Exception('Offer not yet available');
    final payload = await _rv.openEnvelope(envelope: env, pin: pin, saltB64: r.saltB64);
    final offer = {
      'type': payload['type'] as String,
      'sdp': payload['sdp'] as String,
    };
    return JoinOffer(sessionId: r.sessionId, saltB64: r.saltB64, offer: offer);
  }

  Future<void> joinPublishAnswer({
    required String sessionId,
    required String pin,
    required String saltB64,
    required Map<String, String> answer,
  }) async {
    final env = await _rv.sealPayload(sessionId: sessionId, pin: pin, saltB64: saltB64, payload: answer);
    await _rv.putAnswer(sessionId: sessionId, envelope: env);
  }
}


class SyncManifest {
  final int version;
  final int timestampMs;
  final String hashBase64;

  SyncManifest({required this.version, required this.timestampMs, required this.hashBase64});

  static SyncManifest fromVaultJson(String vaultJson) {
    final ts = DateTime.now().millisecondsSinceEpoch;
    final digest = crypto.sha256.convert(utf8.encode(vaultJson));
    return SyncManifest(version: 1, timestampMs: ts, hashBase64: base64Encode(digest.bytes));
  }
}

enum SyncStatus { idle, signaling, connected }

abstract class SyncEvent {
  const SyncEvent();
  factory SyncEvent.localDescriptionReady(String sdp, String type) = LocalDescriptionReadyEvent;
  factory SyncEvent.handshakeComplete() = HandshakeCompleteEvent;
  factory SyncEvent.dataSent() = DataSentEvent;
  factory SyncEvent.dataReceived() = DataReceivedEvent;
  factory SyncEvent.error(String message) = ErrorEvent;
  factory SyncEvent.manifestReceived(SyncManifest manifest) = ManifestReceivedEvent;
  factory SyncEvent.vaultReceived(String json) = VaultReceivedEvent;
  factory SyncEvent.untrustedPeer(String pubKeyB64) = UntrustedPeerEvent;
  factory SyncEvent.peerAuthenticated(String pubKeyB64) = PeerAuthenticatedEvent;
  factory SyncEvent.trustedPeersUpdated(List<String> peers) = TrustedPeersUpdatedEvent;
  factory SyncEvent.vaultRequested() = VaultRequestedEvent;
}

class LocalDescriptionReadyEvent extends SyncEvent {
  final String sdp;
  final String type;
  const LocalDescriptionReadyEvent(this.sdp, this.type);
}

class HandshakeCompleteEvent extends SyncEvent {
  const HandshakeCompleteEvent();
}

class DataSentEvent extends SyncEvent {
  const DataSentEvent();
}

class DataReceivedEvent extends SyncEvent {
  const DataReceivedEvent();
}

class ErrorEvent extends SyncEvent {
  final String message;
  const ErrorEvent(this.message);
}

class ManifestReceivedEvent extends SyncEvent {
  final SyncManifest manifest;
  const ManifestReceivedEvent(this.manifest);
}

class VaultReceivedEvent extends SyncEvent {
  final String json;
  const VaultReceivedEvent(this.json);
}

class UntrustedPeerEvent extends SyncEvent {
  final String pubKeyB64;
  const UntrustedPeerEvent(this.pubKeyB64);
}

class PeerAuthenticatedEvent extends SyncEvent {
  final String pubKeyB64;
  const PeerAuthenticatedEvent(this.pubKeyB64);
}

class TrustedPeersUpdatedEvent extends SyncEvent {
  final List<String> peers;
  const TrustedPeersUpdatedEvent(this.peers);
}

class VaultRequestedEvent extends SyncEvent {
  const VaultRequestedEvent();
}
