import 'package:flutter/material.dart';
import '../encryption.dart';
import '../storage.dart';
import 'home_page.dart';
import 'dart:convert';
import 'dart:typed_data';

class LandingPage extends StatefulWidget {
  @override
  State<LandingPage> createState() => _LandingPageState();
}

class _LandingPageState extends State<LandingPage> {
  final _passwordController = TextEditingController();
  bool creatingNew = false;

  void _createNew() async {
    final password = _passwordController.text;
    if (password.isEmpty) return;

    final salt = HybridEncryption.generateSalt();
    final aesKey = HybridEncryption.deriveKey(password, salt);

    // Encrypt empty database with IV
    final encrypted = HybridEncryption.encryptDatabase(aesKey, jsonEncode([]));
    final cipherBytes = encrypted['cipherBytes']!;
    final iv = encrypted['iv']!;

    final numChunks = (password.length % 3) + 3;
    final chunks = HybridEncryption.splitChunks(cipherBytes, numChunks);
    final shuffled = HybridEncryption.shuffleChunks(chunks, password, salt);

    // Save chunks + salt + IV
    await PasswordStorage.saveDatabase(shuffled, salt, iv);

    Navigator.pushReplacement(
      context,
      MaterialPageRoute(builder: (_) => HomePage(aesKey: aesKey)),
    );
  }

  void _openExisting() async {
    final password = _passwordController.text;
    if (password.isEmpty) return;

    final data = await PasswordStorage.loadDatabase();
    if (data.isEmpty) return;

    final chunks = List<Uint8List>.from(data['chunks']);
    final salt = data['salt'] as Uint8List;
    final iv = data['iv'] as Uint8List;

    final aesKey = HybridEncryption.deriveKey(password, salt);
    final shuffled = HybridEncryption.shuffleChunks(chunks, password, salt);
    final merged = HybridEncryption.mergeChunks(shuffled);

    try {
      HybridEncryption.decryptDatabase(aesKey, merged, iv);

      Navigator.pushReplacement(
        context,
        MaterialPageRoute(builder: (_) => HomePage(aesKey: aesKey)),
      );
    } catch (_) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Failed to decrypt. Wrong password?')),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text('Password Manager')),
      body: Padding(
        padding: EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            TextField(
              controller: _passwordController,
              obscureText: true,
              decoration: InputDecoration(
                labelText: creatingNew ? 'Set Password' : 'Enter Password',
              ),
            ),
            SizedBox(height: 16),
            Row(
              children: [
                ElevatedButton(
                  onPressed: () {
                    creatingNew = true;
                    _createNew();
                  },
                  child: Text('Create New'),
                  style: ElevatedButton.styleFrom(
                    shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(8)),
                    padding: EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                  ),
                ),
                SizedBox(width: 16),
                ElevatedButton(
                  onPressed: _openExisting,
                  child: Text('Open Existing'),
                  style: ElevatedButton.styleFrom(
                    shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(8)),
                    padding: EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}
