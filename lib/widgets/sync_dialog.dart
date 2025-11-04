import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'dart:async';
import 'dart:math';
import 'dart:ui' show FontFeature;
import '/services/sync_service.dart';
import '/services/rendezvous_client.dart' show RendezvousHttpException;

enum SyncRole { host, join }

class SyncDialog extends StatefulWidget {
  final Function(String vaultJson) onReceiveData;
  final String currentVaultJson;
  final SyncRole? initialRole;
  const SyncDialog({
    Key? key,
    required this.onReceiveData,
    required this.currentVaultJson,
    this.initialRole,
  }) : super(key: key);
  @override
  State<SyncDialog> createState() => _SyncDialogState();
}

class _SyncDialogState extends State<SyncDialog> {
  final SyncService _sync = SyncService();

  String _status = 'Idle';
  String? _error;
  String _devicePub = '';
  List<String> _trusted = [];

  String? _pinDisplay;
  String? _pinSessionId;
  String? _pinSaltB64;
  int _pinTtlSec = 0;
  Timer? _ttlTimer;
  int _ttlLeft = 0;

  SyncRole _role = SyncRole.host;

  final TextEditingController _pinCtl = TextEditingController();
  bool _joining = false;

  @override
  void initState() {
    super.initState();
    _role = widget.initialRole ?? _role;
    _init();
  }

  @override
  void dispose() {
    _sync.stop();
    _ttlTimer?.cancel();
    _pinCtl.dispose();
    super.dispose();
  }

  Future<void> _init() async {
    await _sync.init();
    final pub = await _sync.getDevicePublicKeyBase64();
    final peers = await _sync.getTrustedPeers();
    setState(() {
      _devicePub = pub;
      _trusted = peers;
    });
    _sync.events?.listen(_onEvent);
  }

  void _onEvent(SyncEvent e) async {
    if (!mounted) return;
    if (e is HandshakeCompleteEvent) {
      setState(() {
        _status = 'Secure Connection Established';
        _joining = false;
      });
      await _sync.sendManifest(widget.currentVaultJson);
    } else if (e is UntrustedPeerEvent) {
      setState(() {
        _status = 'Untrusted peer. Add their code to trusted peers.';
        _error = 'Untrusted peer public key: ${e.pubKeyB64}';
        _joining = false;
      });
    } else if (e is PeerAuthenticatedEvent) {
      setState(() {
        _status = 'Peer authenticated. Connecting…';
        _error = null;
      });
    } else if (e is ManifestReceivedEvent) {
      final localManifest = SyncManifest.fromVaultJson(widget.currentVaultJson);
      final peerNewer = e.manifest.timestampMs > localManifest.timestampMs ||
          e.manifest.hashBase64 != localManifest.hashBase64;
      if (peerNewer) {
        await _sync.requestVault();
        setState(() => _status = 'Requested vault from peer…');
      } else {
        await _sync.sendVaultData(widget.currentVaultJson);
        setState(() => _status = 'Sent local vault to peer.');
      }
    } else if (e is VaultRequestedEvent) {
      await _sync.sendVaultData(widget.currentVaultJson);
      setState(() => _status = 'Peer requested vault. Sent.');
    } else if (e is VaultReceivedEvent) {
      widget.onReceiveData(e.json);
      if (!mounted) return;
      Navigator.of(context).pop();
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Vault synced successfully!')),
      );
    } else if (e is ErrorEvent) {
      setState(() {
        _error = e.message;
        _status = 'Error';
        _joining = false;
      });
    }
  }

  Future<void> _startPinPairing() async {
    setState(() {
      _status = 'Starting PIN session…';
      _error = null;
      _pinDisplay = null;
      _pinSessionId = null;
      _pinSaltB64 = null;
      _pinTtlSec = 0;
      _ttlLeft = 0;
    });
    try {
      final sess = await _sync.createPinPairingSession();
      setState(() {
        _pinDisplay = sess.pin;
        _pinSessionId = sess.sessionId;
        _pinSaltB64 = sess.saltB64;
        _pinTtlSec = sess.ttlSec;
        _ttlLeft = sess.ttlSec;
      });
      _ttlTimer?.cancel();
      _ttlTimer = Timer.periodic(const Duration(seconds: 1), (_) {
        if (!mounted) return;
        setState(() {
          _ttlLeft = (_ttlLeft - 1).clamp(0, 1 << 30);
          if (_ttlLeft == 0) {
            _status = 'PIN expired. Tap Restart to generate a new PIN.';
            _ttlTimer?.cancel();
          }
        });
      });

      final offer = await _sync.createOffer();
      await _sync.hostPublishOffer(
        sessionId: _pinSessionId!,
        pin: _pinDisplay!,
        saltB64: _pinSaltB64!,
        offer: offer,
      );
      setState(() => _status = 'Waiting for the other device…');

      await _sync.hostWaitForAnswer(
        sessionId: _pinSessionId!,
        pin: _pinDisplay!,
        saltB64: _pinSaltB64!,
        maxWait: Duration(seconds: _pinTtlSec > 0 ? _pinTtlSec : 180),
      );
    } on RendezvousHttpException catch (e) {
      setState(() {
        if (e.statusCode == 410) {
          _error = 'PIN expired. Restart pairing.';
        } else if (e.statusCode == 404) {
          _error = 'Session not found. Restart pairing.';
        } else {
          _error = e.message ?? e.toString();
        }
        _status = 'Error';
      });
    } catch (e) {
      setState(() {
        _error = '$e';
        _status = 'Error';
      });
    }
  }

  Future<void> _joinViaPin(String pin) async {
    if (pin.isEmpty) return;
    if (_joining) return;
    setState(() {
      _joining = true;
      _status = 'Resolving PIN…';
      _error = null;
    });
    try {
      final jo = await _sync.joinFetchOfferByPin(pin);
      setState(() {
        _status = 'Connecting… (offer received)';
        _pinSaltB64 = jo.saltB64;
        _pinSessionId = jo.sessionId;
      });
      final answer = await _sync.createAnswerForRemoteOffer(jo.offer);
      await _sync.joinPublishAnswer(
        sessionId: jo.sessionId,
        pin: pin,
        saltB64: jo.saltB64,
        answer: answer,
      );
      setState(() => _status = 'Waiting for connection…');
    } on RendezvousHttpException catch (e) {
      setState(() {
        if (e.statusCode == 404) {
          _error = 'PIN not found. Make sure the host shared the current PIN.';
        } else if (e.statusCode == 410) {
          _error = 'PIN expired. Ask the host to restart pairing.';
        } else {
          _error = e.message ?? e.toString();
        }
        _status = 'Error';
        _joining = false;
      });
    } catch (e) {
      setState(() {
        _error = '$e';
        _status = 'Error';
        _joining = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final size = MediaQuery.of(context).size;
    final dialogW = size.width * 0.85;
    final dialogH = min(size.height * 0.8, 520.0);

    return AlertDialog(
      content: SizedBox(
        width: dialogW,
        height: dialogH,
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const Text('Device Sync (PIN)', style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
            const SizedBox(height: 8),
            Text('Status: $_status', style: const TextStyle(fontSize: 14)),
            if (_error != null) ...[
              const SizedBox(height: 6),
              Text('Error: $_error', style: const TextStyle(color: Colors.red)),
            ],
            const SizedBox(height: 8),

            ToggleButtons(
              isSelected: [_role == SyncRole.host, _role == SyncRole.join],
              onPressed: (i) => setState(() => _role = i == 0 ? SyncRole.host : SyncRole.join),
              children: const [
                Padding(padding: EdgeInsets.symmetric(horizontal: 12), child: Text('Host')),
                Padding(padding: EdgeInsets.symmetric(horizontal: 12), child: Text('Join')),
              ],
            ),
            const SizedBox(height: 8),

            Expanded(
              child: SingleChildScrollView(
                child: _role == SyncRole.host ? _buildHost() : _buildJoin(),
              ),
            ),
            const SizedBox(height: 8),
            const Text('Verify: Confirm last 4 chars of device ID match on both devices.', style: TextStyle(fontSize: 12)),
            const SizedBox(height: 8),
            OutlinedButton(
              onPressed: () {
                _sync.stop();
                Navigator.of(context).pop();
              },
              child: const Text('Close'),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildHost() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        ElevatedButton.icon(
          onPressed: _startPinPairing,
          icon: const Icon(Icons.lock),
          label: const Text('Start pairing'),
        ),
        if (_pinDisplay != null) ...[
          const SizedBox(height: 8),
          Center(child: Text('PIN: $_pinDisplay', style: const TextStyle(fontSize: 28, fontFeatures: [FontFeature.tabularFigures()]))),
          const SizedBox(height: 4),
          Text('Expires in: ${_ttlLeft}s', textAlign: TextAlign.center),
          const SizedBox(height: 8),
          if (_ttlLeft == 0)
            OutlinedButton.icon(
              onPressed: _startPinPairing,
              icon: const Icon(Icons.refresh),
              label: const Text('Restart pairing'),
            ),
        ],
      ],
    );
  }

  Widget _buildJoin() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const Text('Enter the PIN shown on the other device:'),
        const SizedBox(height: 6),
        TextField(
          controller: _pinCtl,
          keyboardType: TextInputType.number,
          textInputAction: TextInputAction.done,
          maxLength: 8,
          decoration: const InputDecoration(
            labelText: 'PIN (6–8 digits)',
            border: OutlineInputBorder(),
          ),
          onSubmitted: (v) => _joinViaPin(v.trim()),
          enabled: !_joining,
        ),
        const SizedBox(height: 8),
        ElevatedButton(
          onPressed: _joining ? null : () => _joinViaPin(_pinCtl.text.trim()),
          child: Text(_joining ? 'Joining…' : 'Join'),
        ),
      ],
    );
  }
}
