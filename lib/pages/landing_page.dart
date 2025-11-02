import 'dart:isolate';
import 'dart:io';
import 'package:flutter/material.dart';
import '/services/crypto_service.dart';
import '/services/storage_service.dart';
import '/pages/home_page.dart';
import 'package:cryptography/cryptography.dart';
import 'package:qsafevault/services/theme_service.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:http/http.dart' as http;
import 'dart:convert';
import 'package:path_provider/path_provider.dart';
import 'package:flutter/services.dart';

class LandingPage extends StatefulWidget {
  final StorageService storage;
  final CryptoService cryptoService;
  const LandingPage(
      {Key? key, required this.storage, required this.cryptoService})
      : super(key: key);
  @override
  State<LandingPage> createState() => _LandingPageState();
}

class _LandingPageState extends State<LandingPage> {
  bool _busy = false;
  double _progress = 0.0;
  String _status = "";
  List<String> _recentVaults = [];
  static const int _maxRecents = 10;

  bool _isVaultPath(String p) => p.toLowerCase().endsWith('.vault');
  Future<bool> _pathExists(String p) async => _isVaultPath(p) ? File(p).exists() : Directory(p).exists();
  void _toast(String msg) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(msg)));
  }

  @override
  void initState() {
    super.initState();
    ThemeService.instance.init();
    _loadRecentVaults();
  }

  Future<void> _loadRecentVaults() async {
    try {
      final dir = await getApplicationDocumentsDirectory();
      final f = File('${dir.path}/recent_vaults.json');
      if (await f.exists()) {
        final list = (jsonDecode(await f.readAsString()) as List).cast<String>();
        _recentVaults = list;
      }
    } catch (_) {}
    await _pruneRecentsIfMissing();
    if (mounted) setState(() {});
  }

  Future<void> _pruneRecentsIfMissing() async {
    final filtered = <String>[];
    for (final p in _recentVaults) {
      if (await _pathExists(p)) filtered.add(p);
    }
    if (filtered.length != _recentVaults.length) {
      _recentVaults = filtered;
      await _saveRecentVaults();
    }
  }

  Future<void> _saveRecentVaults() async {
    try {
      final dir = await getApplicationDocumentsDirectory();
      final f = File('${dir.path}/recent_vaults.json');
      await f.writeAsString(jsonEncode(_recentVaults), flush: true);
    } catch (_) {}
  }

  void _addRecent(String path) {
    setState(() {
      _recentVaults.remove(path);
      _recentVaults.insert(0, path);
      if (_recentVaults.length > _maxRecents) {
        _recentVaults = _recentVaults.take(_maxRecents).toList();
      }
    });
    _saveRecentVaults();
  }

  Future<String?> _askForVaultName() async {
    final ctl = TextEditingController();
    return showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Vault name'),
        content: TextField(
          controller: ctl,
          decoration: const InputDecoration(hintText: 'e.g., MyVault'),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.of(ctx).pop(null), child: const Text('Cancel')),
          ElevatedButton(
            onPressed: () {
              final n = ctl.text.trim();
              if (n.isEmpty) return;
              Navigator.of(ctx).pop(n);
            },
            child: const Text('OK'),
          ),
        ],
      ),
    );
  }

  Future<void> _createDbFlow() async {
    try {
      final name = await _askForVaultName();
      if (name == null) return;

      final dir = await widget.storage.pickDirectoryWithFallback();
      final vaultPath = '$dir/${name.endsWith('.vault') ? name : '$name.vault'}';

      final createPassword = await _askForPassword(confirm: true);
      if (createPassword == null) return;

      if (await File(vaultPath).exists()) {
        final ok = await _askConfirmationDialog(
              title: 'Overwrite file?',
              message: 'A vault named "$name" already exists here. Overwrite it?') ?? false;
        if (!ok) return;
      }

      setState(() {
        _busy = true;
        _progress = 0.0;
        _status = "Creating secure database… (est. ~30s)";
      });
      _simulateProgress(duration: const Duration(seconds: 30));

      final error = await _createEmptyDbWithIsolate(
        folderPath: vaultPath,
        password: createPassword,
        parts: 3,
        iterations: 0,
        memoryKb: 0,
        parallelism: 2,
      );
      if (error != null) throw Exception(error);

      setState(() {
        _status = "Finalizing and deriving key…";
        _progress = 0.85;
      });

      final result = await _deriveKeyWithIsolate(vaultPath, createPassword);

      setState(() {
        _progress = 1.0;
        _status = "Database ready!";
      });
      await Future.delayed(const Duration(milliseconds: 500));
      if (!mounted) return;

      _addRecent(vaultPath);

      await Navigator.of(context).push(MaterialPageRoute(
        builder: (_) => HomePage(
          storage: widget.storage,
          cryptoService: widget.cryptoService,
          folderPath: vaultPath,
          secretKey: result.key,
          initialJson: result.plaintext,
        ),
      ));
    } catch (e) {
      _showError(e.toString());
    } finally {
      if (mounted) {
        setState(() {
          _busy = false;
          _progress = 0.0;
          _status = "";
        });
      }
    }
  }

  Future<String?> _createEmptyDbWithIsolate({
    required String folderPath,
    required String password,
    int parts = 10,
    int memoryKb = 64,
    int iterations = 3,
    int parallelism = 2,
  }) async {
    final receivePort = ReceivePort();
    final token = RootIsolateToken.instance;
    await Isolate.spawn(
      StorageService.createEmptyDbIsolateEntry,
      [
        receivePort.sendPort,
        folderPath,
        password,
        parts,
        memoryKb,
        iterations,
        parallelism,
        token,
      ],
    );
    final message = await receivePort.first;
    if (message == null) return null;
    return message.toString();
  }

  Future<void> _openDbFlow({String? vaultPath}) async {
    setState(() {
      _busy = true;
      _progress = 0.0;
      _status = "Opening database… (est. ~3s)";
    });
    try {
      final path = vaultPath ?? await widget.storage.pickVaultFileForOpen();
      if (path == null) return;

      if (!await _pathExists(path)) {
        _toast('Vault not found. It may have been moved or deleted.');
        setState(() {
          _recentVaults.remove(path);
        });
        await _saveRecentVaults();
        final picked = await widget.storage.pickVaultFileForOpen();
        if (picked == null) return;
        return await _openDbFlow(vaultPath: picked);
      }

      final password = await _askForPassword(confirm: false);
      if (password == null) return;

      _simulateProgress(duration: const Duration(seconds: 3));
      final result = await _deriveKeyWithIsolate(path, password);

      setState(() {
        _progress = 1.0;
        _status = "Unlocked!";
      });
      await Future.delayed(const Duration(milliseconds: 500));
      if (!mounted) return;

      _addRecent(path);

      await Navigator.of(context).push(MaterialPageRoute(
        builder: (_) => HomePage(
          storage: widget.storage,
          cryptoService: widget.cryptoService,
          folderPath: path,
          secretKey: result.key,
          initialJson: result.plaintext,
        ),
      ));
    } catch (e) {
      _showError("Failed to open DB: ${e.toString()}");
    } finally {
      if (mounted) {
        setState(() {
          _busy = false;
          _progress = 0.0;
          _status = "";
        });
      }
    }
  }

  Future<({String plaintext, SecretKey key})> _deriveKeyWithIsolate(
    String folderPath, String password) async {
    final receivePort = ReceivePort();
    final token = RootIsolateToken.instance;
    await Isolate.spawn(
        _deriveKeyIsolateEntry, [receivePort.sendPort, folderPath, password, token]);
    final result = await receivePort.first as Map<String, dynamic>;
    if (result['ok'] == false) {
      throw Exception(result['error']);
    }
    final key = SecretKey(result['keyBytes'] as List<int>);
    final plaintext = result['plaintext'] as String;
    return (plaintext: plaintext, key: key);
  }

  static Future<void> _deriveKeyIsolateEntry(List<dynamic> args) async {
    final sendPort = args[0] as SendPort;
    final folderPath = args[1] as String;
    final password = args[2] as String;
    final RootIsolateToken? token = args.length > 3 ? args[3] as RootIsolateToken? : null;
    if (token != null) {
      BackgroundIsolateBinaryMessenger.ensureInitialized(token);
    }
    try {
      final storage = StorageService(CryptoService());
      final result =
          await storage.openDb(folderPath: folderPath, password: password);
      final keyBytes = await result.key.extractBytes();
      sendPort.send(
          {'ok': true, 'plaintext': result.plaintext, 'keyBytes': keyBytes});
    } catch (e) {
      sendPort.send({'ok': false, 'error': e.toString()});
    }
  }

  void _simulateProgress({required Duration duration}) {
    final startTime = DateTime.now();
    Future.doWhile(() async {
      if (!_busy) return false;
      final elapsed = DateTime.now().difference(startTime);
      final fraction = elapsed.inMilliseconds / duration.inMilliseconds;
      if (fraction >= 0.7) return false;
      if (mounted) setState(() => _progress = fraction.clamp(0.0, 1.0));
      await Future.delayed(const Duration(milliseconds: 200));
      return true;
    });
  }

  Future<String?> _askForPassword({required bool confirm}) async {
    final passwordCtl = TextEditingController();
    final password2Ctl = TextEditingController();
    final formKey = GlobalKey<FormState>();
    double strength = 0;
    String breachMsg = '';
    bool checkingBreach = false;
    double _score(String p) {
      if (p.isEmpty) return 0;
      int classes = 0;
      if (RegExp(r'[a-z]').hasMatch(p)) classes++;
      if (RegExp(r'[A-Z]').hasMatch(p)) classes++;
      if (RegExp(r'\d').hasMatch(p)) classes++;
      if (RegExp(r'[^A-Za-z0-9]').hasMatch(p)) classes++;
      double lenFactor = (p.length / 20).clamp(0.0, 1.0);
      return ((classes / 4) * 0.6 + lenFactor * 0.4).clamp(0.0, 1.0);
    }

    Future<void> _checkBreach(String p) async {
      breachMsg = '';
      if (p.length < 12) return;
      checkingBreach = true;
    }

    bool _badPatterns(String p) {
      final lowered = p.toLowerCase();
      const common = ['password', '123456', 'qwerty', 'letmein', 'admin'];
      if (common.any((w) => lowered.contains(w))) return true;
      if (RegExp(r'(.)\1{3,}').hasMatch(p)) return true; 
      if (RegExp(r'^\d{6,}$').hasMatch(p)) return true;
      return false;
    }
    final res = await showDialog<String?>(
      context: context,
      builder: (context) => StatefulBuilder(
        builder: (ctx, setLocal) => AlertDialog(
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
                  onChanged: (v) async {
                    setLocal(() => strength = _score(v));
                    if (v.length >= 12) {
                      setLocal(() { checkingBreach = true; breachMsg = ''; });
                      try {
                        final sha1 = crypto.sha1.convert(v.codeUnits).toString().toUpperCase();
                        final prefix = sha1.substring(0, 5);
                        final suffix = sha1.substring(5);
                        final resp = await http.get(Uri.parse('https://api.pwnedpasswords.com/range/$prefix'));
                        if (resp.statusCode == 200) {
                          final found = resp.body.split('\n').any((line) => line.split(':').first.trim() == suffix);
                          setLocal(() => breachMsg = found ? 'Found in breaches' : 'Not found in known breaches');
                        }
                      } catch (_) {
                      } finally {
                        setLocal(() => checkingBreach = false);
                      }
                    } else {
                      setLocal(() { breachMsg = ''; checkingBreach = false; });
                    }
                  },
                  validator: (v) {
                    if (v == null || v.length < 12) return 'Password must be at least 12 characters';
                    if (_badPatterns(v)) return 'Avoid common/monotonic patterns';
                    return null;
                  },
                ),
                const SizedBox(height: 8),
                LinearProgressIndicator(value: strength, minHeight: 6),
                const SizedBox(height: 4),
                Align(
                  alignment: Alignment.centerLeft,
                  child: Text(
                    checkingBreach ? 'Checking breach…' : breachMsg,
                    style: TextStyle(color: (breachMsg.contains('breach')) ? Colors.red : Colors.grey, fontSize: 12),
                  ),
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
      ),
    );
    return res;
  }
  Future<bool?> _askConfirmationDialog(
      {required String title, required String message}) async {
    return showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(title),
        content: Text(message),
        actions: [
          TextButton(
              onPressed: () => Navigator.of(ctx).pop(false),
              child: const Text('Cancel')),
          ElevatedButton(
              onPressed: () => Navigator.of(ctx).pop(true),
              child: const Text('Proceed')),
        ],
      ),
    );
  }
  void _showError(String msg) {
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(
      content: Text(msg),
      backgroundColor: Colors.red.shade700,
    ));
  }

  Widget _buildPrimaryButton({
    required String label,
    required IconData icon,
    required VoidCallback? onTap,
  }) {
    final theme = Theme.of(context);
    final bg = theme.colorScheme.primary;
    final fg = theme.colorScheme.onPrimary;
    final disabled = onTap == null;

    return ConstrainedBox(
      constraints: const BoxConstraints(minHeight: 40),
      child: Material(
        color: disabled ? theme.disabledColor : bg,
        borderRadius: BorderRadius.circular(8),
        child: InkWell(
          borderRadius: BorderRadius.circular(8),
          onTap: disabled ? null : onTap,
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(icon, color: fg),
                const SizedBox(width: 8),
                Text(label, style: TextStyle(color: fg)),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildOpenSplitButton() {
    final theme = Theme.of(context);
    final bg = theme.colorScheme.primary;
    final fg = theme.colorScheme.onPrimary;
    final disabled = _busy;
    final label = _recentVaults.isNotEmpty ? 'Open Last DB' : 'Open DB';

    return ConstrainedBox(
      constraints: const BoxConstraints(minHeight: 40),
      child: Material(
        color: disabled ? theme.disabledColor : bg,
        borderRadius: BorderRadius.circular(8),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            InkWell(
              borderRadius: const BorderRadius.only(
                topLeft: Radius.circular(8),
                bottomLeft: Radius.circular(8),
              ),
              onTap: disabled
                  ? null
                  : () async {
                      if (_recentVaults.isNotEmpty) {
                        final p = _recentVaults.first;
                        if (!await _pathExists(p)) {
                          _toast('Last vault not found. It may have been moved or deleted.');
                          setState(() => _recentVaults.removeAt(0));
                          await _saveRecentVaults();
                          await _openDbFlow();
                        } else {
                          await _openDbFlow(vaultPath: p);
                        }
                      } else {
                        await _openDbFlow();
                      }
                    },
              child: Padding(
                padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Icon(Icons.folder_open, color: fg),
                    const SizedBox(width: 8),
                    Text(label, style: TextStyle(color: fg)),
                  ],
                ),
              ),
            ),
            Container(width: 1, height: 40, color: fg.withOpacity(0.25)),
            PopupMenuButton<String>(
              tooltip: 'Recent vaults',
              icon: Icon(Icons.arrow_drop_down, color: fg),
              onSelected: (p) async {
                if (p == '__other__') {
                  await _openDbFlow();
                  return;
                }
                if (!await _pathExists(p)) {
                  _toast('Vault not found. Removed from recent.');
                  setState(() => _recentVaults.remove(p));
                  await _saveRecentVaults();
                  return;
                }
                await _openDbFlow(vaultPath: p);
              },
              itemBuilder: (ctx) {
                final items = <PopupMenuEntry<String>>[];
                for (final p in _recentVaults) {
                  final name = p.split(Platform.pathSeparator).last;
                  items.add(PopupMenuItem(value: p, child: Text(name),));
                }
                if (items.isNotEmpty) items.add(const PopupMenuDivider());
                items.add(const PopupMenuItem(value: '__other__', child: Text('Open other…')));
                return items;
              },
            ),
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return WillPopScope(
      onWillPop: () async {
        if (_busy) {
          setState(() {
            _busy = false;
            _progress = 0.0;
            _status = "";
          });
        }
        return true;
      },
      child: Scaffold(
        appBar: AppBar(
          title: const Text('Q-Safe Vault'),
          actions: [
            IconButton(
              tooltip: 'Toggle light/dark',
              icon: const Icon(Icons.brightness_6),
              onPressed: () => ThemeService.instance.toggleLightDark(),
            ),
            PopupMenuButton<AppThemeMode>(
              tooltip: 'Theme',
              onSelected: (m) => ThemeService.instance.setMode(m),
              itemBuilder: (ctx) => const [
                PopupMenuItem(value: AppThemeMode.system, child: Text('System')),
                PopupMenuItem(value: AppThemeMode.light, child: Text('Light')),
                PopupMenuItem(value: AppThemeMode.dark, child: Text('Dark')),
              ],
            ),
          ],
        ),
        body: Center(
          child: _busy
              ? Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    Text("$_status\n${(_progress * 100).toStringAsFixed(0)}%",
                        textAlign: TextAlign.center),
                    const SizedBox(height: 16),
                    SizedBox(
                      width: 250,
                      child: LinearProgressIndicator(value: _progress),
                    ),
                  ],
                )
              : Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    _buildPrimaryButton(
                      label: 'Create DB',
                      icon: Icons.add,
                      onTap: _busy ? null : _createDbFlow,
                    ),
                    const SizedBox(height: 16),
                    _buildOpenSplitButton(),
                  ],
                ),
        ),
      ),
    );
  }
}
