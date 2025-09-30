import 'dart:convert';
import 'dart:isolate';
import 'package:flutter/material.dart';
import '/services/crypto_service.dart';
import '/services/storage_service.dart';
import '/pages/home_page.dart';
import 'package:cryptography/cryptography.dart';

class LandingPage extends StatefulWidget {
  final StorageService storage;
  final CryptoService cryptoService;
  const LandingPage({Key? key, required this.storage, required this.cryptoService}) : super(key: key);

  @override
  State<LandingPage> createState() => _LandingPageState();
}

class _LandingPageState extends State<LandingPage> {
  bool _busy = false;
  double _progress = 0.0;

  Future<void> _createDbFlow() async {
    setState(() {
      _busy = true;
      _progress = 0.0;
    });

    try {
      final folder = await widget.storage.pickDirectoryWithFallback();
      final password = await _askForPassword(confirm: true);
      if (password == null) return;

      await widget.storage.createEmptyDb(
        folderPath: folder,
        password: password,
        iterations: 200000,
        parts: 3,
      );

      final result = await _deriveKeyWithIsolate(folder, password);

      Navigator.of(context).pushReplacement(MaterialPageRoute(
        builder: (_) => HomePage(
          storage: widget.storage,
          cryptoService: widget.cryptoService,
          folderPath: folder,
          secretKey: result.key,
          initialJson: result.plaintext,
        ),
      ));
    } catch (e) {
      _showError(e.toString());
    } finally {
      setState(() => _busy = false);
    }
  }

  Future<void> _openDbFlow() async {
    setState(() {
      _busy = true;
      _progress = 0.0;
    });

    try {
      final folder = await widget.storage.pickDirectoryWithFallback();
      final password = await _askForPassword(confirm: false);
      if (password == null) return;

      final result = await _deriveKeyWithIsolate(folder, password);

      Navigator.of(context).pushReplacement(MaterialPageRoute(
        builder: (_) => HomePage(
          storage: widget.storage,
          cryptoService: widget.cryptoService,
          folderPath: folder,
          secretKey: result.key,
          initialJson: result.plaintext,
        ),
      ));
    } catch (e) {
      _showError(e.toString());
    } finally {
      setState(() => _busy = false);
    }
  }

  Future<({String plaintext, SecretKey key})> _deriveKeyWithIsolate(
      String folderPath, String password) async {
    final receivePort = ReceivePort();
    await Isolate.spawn(_deriveKeyIsolateEntry, [receivePort.sendPort, folderPath, password]);
    final result = await receivePort.first as Map<String, dynamic>;

    final key = SecretKey(result['keyBytes'] as List<int>);
    final plaintext = result['plaintext'] as String;
    return (plaintext: plaintext, key: key);
  }

  static Future<void> _deriveKeyIsolateEntry(List<dynamic> args) async {
    final sendPort = args[0] as SendPort;
    final folderPath = args[1] as String;
    final password = args[2] as String;

    final storage = StorageService(CryptoService());
    final result = await storage.openDb(folderPath: folderPath, password: password);

    final keyBytes = await result.key.extractBytes();
    sendPort.send({'plaintext': result.plaintext, 'keyBytes': keyBytes});
  }

  Future<String?> _askForPassword({required bool confirm}) async {
    final passwordCtl = TextEditingController();
    final password2Ctl = TextEditingController();
    final formKey = GlobalKey<FormState>();
    final res = await showDialog<String?>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(confirm ? 'Create DB - set password' : 'Open DB - enter password'),
        content: Form(
          key: formKey,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              TextFormField(
                controller: passwordCtl,
                decoration: const InputDecoration(labelText: 'Password'),
                obscureText: true,
                validator: (v) => (v == null || v.length < 8) ? 'Password >= 8 chars' : null,
              ),
              if (confirm)
                TextFormField(
                  controller: password2Ctl,
                  decoration: const InputDecoration(labelText: 'Confirm password'),
                  obscureText: true,
                  validator: (v) => (v != passwordCtl.text) ? 'Passwords do not match' : null,
                ),
            ],
          ),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.of(context).pop(null), child: const Text('Cancel')),
          ElevatedButton(
            onPressed: () {
              if (formKey.currentState?.validate() ?? false) {
                Navigator.of(context).pop(passwordCtl.text);
              }
            },
            child: const Text('OK'),
          )
        ],
      ),
    );
    return res;
  }

  void _showError(String msg) {
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(msg)));
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Q-Safe Vault')),
      body: Center(
        child: _busy
            ? Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: const [
                  Text('Processing...'),
                  SizedBox(height: 16),
                  CircularProgressIndicator(),
                ],
              )
            : Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  ElevatedButton.icon(
                    onPressed: _createDbFlow,
                    icon: const Icon(Icons.add),
                    label: const Text('Create DB'),
                  ),
                  const SizedBox(height: 16),
                  ElevatedButton.icon(
                    onPressed: _openDbFlow,
                    icon: const Icon(Icons.folder_open),
                    label: const Text('Open DB'),
                  ),
                ],
              ),
      ),
    );
  }
}
