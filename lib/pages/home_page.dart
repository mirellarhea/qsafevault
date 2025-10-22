import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '/models/password_entry.dart';
import '/services/crypto_service.dart';
import '/services/storage_service.dart';
import 'package:cryptography/cryptography.dart';
import '/widgets/entry_form.dart';
import 'package:qsafevault/services/theme_service.dart';
class HomePage extends StatefulWidget {
  final StorageService storage;
  final CryptoService cryptoService;
  final String folderPath;
  final SecretKey secretKey;
  final String initialJson;
  const HomePage({
    Key? key,
    required this.storage,
    required this.cryptoService,
    required this.folderPath,
    required this.secretKey,
    required this.initialJson,
  }) : super(key: key);
  @override
  State<HomePage> createState() => _HomePageState();
}
class _HomePageState extends State<HomePage> {
  late List<PasswordEntry> _entries;
  String _searchQuery = "";
  bool _saving = false;
  @override
  void initState() {
    super.initState();
    try {
      _entries = PasswordEntry.listFromJson(widget.initialJson);
    } catch (_) {
      _entries = [];
    }
  }
  List<PasswordEntry> get _filteredEntries {
    if (_searchQuery.isEmpty) return _entries;
    final q = _searchQuery.toLowerCase();
    return _entries.where((e) {
      return e.site.toLowerCase().contains(q) ||
          e.username.toLowerCase().contains(q) ||
          e.email.toLowerCase().contains(q) ||
          e.password.toLowerCase().contains(q);
    }).toList();
  }
  Future<void> _saveToDisk() async {
    setState(() => _saving = true);
    try {
      final json = PasswordEntry.listToJson(_entries);
      await widget.storage.saveDb(
        folderPath: widget.folderPath,
        key: widget.secretKey,
        jsonDb: json,
      );
      ScaffoldMessenger.of(context)
          .showSnackBar(const SnackBar(content: Text('Saved')));
    } catch (e) {
      ScaffoldMessenger.of(context)
          .showSnackBar(SnackBar(content: Text('Save error: $e')));
    } finally {
      setState(() => _saving = false);
    }
  }
  void _addEntry() {
    showDialog(
      context: context,
      builder: (_) => EntryForm(
        onSave: (entry) {
          setState(() => _entries.add(entry));
          _saveToDisk();
        },
      ),
    );
  }
  void _remindSave() {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: const Text('Remember to tap Save (top-right) to persist changes'),
        action: SnackBarAction(label: 'Save', onPressed: _saveToDisk),
        duration: const Duration(seconds: 4),
      ),
    );
  }
  void _editEntry(PasswordEntry e) {
    showDialog(
      context: context,
      builder: (_) => EntryForm(
        existing: e,
        onSave: (entry) {
          setState(() {
            final idx = _entries.indexWhere((x) => x.id == entry.id);
            if (idx >= 0) _entries[idx] = entry;
          });
          _remindSave();
        },
      ),
    );
  }
  void _deleteEntry(PasswordEntry e) {
    showDialog(
      context: context,
      builder: (_) => AlertDialog(
        title: const Text('Delete'),
        content: const Text('Are you sure you want to delete this entry?'),
        actions: [
          TextButton(
              onPressed: () => Navigator.of(context).pop(),
              child: const Text('Cancel')),
          ElevatedButton(
            onPressed: () {
              setState(() => _entries.removeWhere((x) => x.id == e.id));
              _remindSave();
              Navigator.of(context).pop();
            },
            child: const Text('Delete'),
          ),
        ],
      ),
    );
  }
  void _deleteDerivedKey() {
    showDialog(
      context: context,
      builder: (_) => AlertDialog(
        title: const Text('Delete Derived Key'),
        content: const Text(
            'This will remove the derived key file. You will need to re-enter your password to access the vault again.'),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            style: ElevatedButton.styleFrom(backgroundColor: Colors.red),
            onPressed: () async {
              Navigator.of(context).pop();
              try {
                await widget.storage.deleteDerivedKey(widget.folderPath);
                if (mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('Derived key deleted')),
                  );
                  Navigator.of(context).popUntil((route) => route.isFirst);
                }
              } catch (e) {
                if (mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(content: Text('Error deleting key: $e')),
                  );
                }
              }
            },
            child: const Text('Delete'),
          ),
        ],
      ),
    );
  }
  Widget _row(PasswordEntry e) {
    final primary = e.username.isNotEmpty ? e.username : e.email;
    return ListTile(
      title: Text(e.site),
      subtitle: Text(primary),
      trailing: Wrap(spacing: 8, children: [
        IconButton(
            onPressed: () => _editEntry(e), icon: const Icon(Icons.edit)),
        IconButton(
            onPressed: () => _deleteEntry(e), icon: const Icon(Icons.delete)),
      ]),
      onTap: () {
        bool obscure = true;
        showDialog(
          context: context,
          builder: (_) => StatefulBuilder(
            builder: (context, setState) => AlertDialog(
              title: Text(e.site),
              content: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  _copyRow(label: "Username", value: e.username),
                  const SizedBox(height: 6),
                  _copyRow(label: "Email", value: e.email),
                  const SizedBox(height: 6),
                  Row(
                    crossAxisAlignment: CrossAxisAlignment.center,
                    children: [
                      Expanded(
                        child: Text(
                          obscure
                              ? "Password: ${"•" * e.password.length}"
                              : "Password: ${e.password}",
                          style: const TextStyle(fontFamily: 'monospace'),
                        ),
                      ),
                      IconButton(
                        icon: Icon(
                            obscure ? Icons.visibility : Icons.visibility_off),
                        onPressed: () => setState(() => obscure = !obscure),
                      ),
                      IconButton(
                        icon: const Icon(Icons.copy),
                        onPressed: () async {
                          await Clipboard.setData(
                              ClipboardData(text: e.password));
                          ScaffoldMessenger.of(context).showSnackBar(
                            const SnackBar(content: Text('Password copied')),
                          );
                        },
                      ),
                    ],
                  ),
                ],
              ),
              actions: [
                TextButton(
                    onPressed: () => Navigator.of(context).pop(),
                    child: const Text('Close')),
              ],
            ),
          ),
        );
      },
    );
  }
  Widget _copyRow({required String label, required String value}) {
    return Row(
      children: [
        Expanded(
          child: Text(
            "$label: $value",
            overflow: TextOverflow.ellipsis,
          ),
        ),
        if (value.isNotEmpty)
          IconButton(
            icon: const Icon(Icons.copy),
            onPressed: () async {
              await Clipboard.setData(ClipboardData(text: value));
              ScaffoldMessenger.of(context).showSnackBar(
                SnackBar(content: Text('$label copied')),
              );
            },
          ),
      ],
    );
  }
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: TextField(
          decoration: const InputDecoration(
            hintText: 'Search...',
            border: InputBorder.none,
          ),
          onChanged: (val) => setState(() => _searchQuery = val),
        ),
        actions: [
          IconButton(
            tooltip: 'Toggle light/dark',
            icon: const Icon(Icons.brightness_6),
            onPressed: () => ThemeService.instance.toggleLightDark(),
          ),
          IconButton(onPressed: _addEntry, icon: const Icon(Icons.add)),
          IconButton(
            onPressed: _saveToDisk,
            icon: _saving
                ? const SizedBox(
                    width: 18,
                    height: 18,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : const Icon(Icons.save),
          ),
        ],
      ),
      body: _filteredEntries.isEmpty
          ? const Center(child: Text("No entries found"))
          : ListView.separated(
              itemCount: _filteredEntries.length,
              separatorBuilder: (_, __) => const Divider(),
              itemBuilder: (_, i) => _row(_filteredEntries[i]),
            ),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: _deleteDerivedKey,
        icon: const Icon(Icons.lock_reset),
        label: const Text("Delete Key"),
      ),
      floatingActionButtonLocation: FloatingActionButtonLocation.centerFloat,
    );
  }
}
