import 'package:flutter/material.dart';
import 'dart:convert';
import 'dart:typed_data';
import '../encryption.dart';
import '../storage.dart';

class HomePage extends StatefulWidget {
  final Uint8List aesKey;

  HomePage({required this.aesKey, Key? key}) : super(key: key);

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  List<Map<String, String>> entries = [];

  // Persistent controllers
  Map<int, TextEditingController> usernameControllers = {};
  Map<int, TextEditingController> emailControllers = {};
  Map<int, TextEditingController> passwordControllers = {};

  @override
  void initState() {
    super.initState();
    _loadDatabase();
  }

  @override
  void dispose() {
    usernameControllers.values.forEach((c) => c.dispose());
    emailControllers.values.forEach((c) => c.dispose());
    passwordControllers.values.forEach((c) => c.dispose());
    super.dispose();
  }

  void _loadDatabase() async {
    final data = await PasswordStorage.loadDatabase();
    if (data.isEmpty) return;

    final chunks = List<Uint8List>.from(data['chunks']);
    final salt = data['salt'] as Uint8List;
    final iv = data['iv'] as Uint8List;

    final shuffled = HybridEncryption.shuffleChunks(
        chunks, utf8.decode(widget.aesKey), salt);
    final merged = HybridEncryption.mergeChunks(shuffled);

    try {
      final decrypted =
          HybridEncryption.decryptDatabase(widget.aesKey, merged, iv);
      setState(() {
        entries = List<Map<String, String>>.from(jsonDecode(decrypted));
        // Initialize controllers
        for (int i = 0; i < entries.length; i++) {
          usernameControllers[i] = TextEditingController(text: entries[i]['username']);
          emailControllers[i] = TextEditingController(text: entries[i]['email']);
          passwordControllers[i] = TextEditingController(text: entries[i]['password']);
        }
      });
    } catch (_) {}
  }

  void _addEntry() {
    setState(() {
      entries.add({'username': '', 'email': '', 'password': ''});
      final index = entries.length - 1;
      usernameControllers[index] = TextEditingController();
      emailControllers[index] = TextEditingController();
      passwordControllers[index] = TextEditingController();
    });
  }

  void _saveDatabase() async {
    // Update entries from controllers
    for (int i = 0; i < entries.length; i++) {
      entries[i]['username'] = usernameControllers[i]?.text ?? '';
      entries[i]['email'] = emailControllers[i]?.text ?? '';
      entries[i]['password'] = passwordControllers[i]?.text ?? '';
    }

    final jsonData = jsonEncode(entries);
    final encrypted = HybridEncryption.encryptDatabase(widget.aesKey, jsonData);
    final cipherBytes = encrypted['cipherBytes']!;
    final iv = encrypted['iv']!;
    final numChunks = (entries.length % 3) + 3;
    final chunks = HybridEncryption.splitChunks(cipherBytes, numChunks);
    final shuffled = HybridEncryption.shuffleChunks(
        chunks, utf8.decode(widget.aesKey), HybridEncryption.generateSalt());

    await PasswordStorage.saveDatabase(shuffled, HybridEncryption.generateSalt(), iv);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text('Passwords'),
        actions: [
          ElevatedButton(
            onPressed: _saveDatabase,
            child: Icon(Icons.save),
            style: ElevatedButton.styleFrom(
              shape: CircleBorder(),
              padding: EdgeInsets.all(12),
            ),
          ),
        ],
      ),
      body: ListView.builder(
        itemCount: entries.length,
        itemBuilder: (context, index) {
          final entry = entries[index];
          return Padding(
            padding: const EdgeInsets.all(8.0),
            child: Column(
              children: [
                TextField(
                  decoration: InputDecoration(labelText: 'Username'),
                  controller: usernameControllers[index],
                ),
                TextField(
                  decoration: InputDecoration(labelText: 'Email'),
                  controller: emailControllers[index],
                ),
                TextField(
                  decoration: InputDecoration(labelText: 'Password'),
                  controller: passwordControllers[index],
                  obscureText: false, // visible
                ),
                Divider(),
              ],
            ),
          );
        },
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: _addEntry,
        child: Icon(Icons.add),
      ),
    );
  }
}
