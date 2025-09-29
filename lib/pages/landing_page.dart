import 'dart:convert';

import 'package:flutter/material.dart';
import '/services/crypto_service.dart';
import '/services/storage_service.dart';
import '/pages/home_page.dart';

class LandingPage extends StatefulWidget {
  final StorageService storage;
  final CryptoService cryptoService;
  const LandingPage({Key? key, required this.storage, required this.cryptoService}) : super(key: key);

  @override
  State<LandingPage> createState() => _LandingPageState();
}

class _LandingPageState extends State<LandingPage> {
  bool _busy = false;

  Future<void> _createDbFlow() async {
    setState(() => _busy = true);
    try {
      final folder = await widget.storage.pickDirectoryWithFallback();
      final password = await _askForPassword(confirm: true);
      if (password == null) return;
      await widget.storage.createEmptyDb(folderPath: folder, password: password, iterations: 200000, parts: 3);
      final json = await widget.storage.openDb(folderPath: folder, password: password);
      Navigator.of(context).pushReplacement(MaterialPageRoute(
        builder: (_) => HomePage(
          storage: widget.storage,
          cryptoService: widget.cryptoService,
          folderPath: folder,
          password: password,
          initialJson: json,
        ),
      ));
    } catch (e) {
      _showError(e.toString());
    } finally {
      setState(() => _busy = false);
    }
  }

  Future<void> _openDbFlow() async {
    setState(() => _busy = true);
    try {
      final folder = await widget.storage.pickDirectoryWithFallback();
      final password = await _askForPassword(confirm: false);
      if (password == null) return;
      final json = await widget.storage.openDb(folderPath: folder, password: password);
      Navigator.of(context).pushReplacement(MaterialPageRoute(
        builder: (_) => HomePage(
          storage: widget.storage,
          cryptoService: widget.cryptoService,
          folderPath: folder,
          password: password,
          initialJson: json,
        ),
      ));
    } catch (e) {
      _showError(e.toString());
    } finally {
      setState(() => _busy = false);
    }
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
      appBar: AppBar(title: const Text('Password Manager — Landing')),
      body: Center(
        child: _busy
            ? const CircularProgressIndicator()
            : Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  ElevatedButton.icon(onPressed: _createDbFlow, icon: const Icon(Icons.add), label: const Text('Create DB')),
                  const SizedBox(height: 16),
                  ElevatedButton.icon(onPressed: _openDbFlow, icon: const Icon(Icons.folder_open), label: const Text('Open DB')),
                ],
              ),
      ),
    );
  }
}
