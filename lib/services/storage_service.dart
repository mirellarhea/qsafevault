import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'dart:math';
import 'dart:isolate';
import 'package:cryptography/cryptography.dart';
import 'package:file_picker/file_picker.dart';
import 'package:path_provider/path_provider.dart';
import 'package:synchronized/synchronized.dart';
import 'crypto_service.dart';

class StorageService {
  final CryptoService cryptoService;
  StorageService(this.cryptoService);

  static const metaFileName = 'pwdb.meta.json';
  static const baseEncryptedName = 'pwdb.enc';
  static const backupSuffix = '.bak';
  static const derivedKeyFileName = 'derived.key';

  final _lock = Lock();

  Future<String> pickDirectoryWithFallback() async {
    try {
      final selected = await FilePicker.platform.getDirectoryPath();
      if (selected != null && selected.isNotEmpty) return selected;
    } catch (_) {}
    final appDoc = await getApplicationDocumentsDirectory();
    final dir = Directory('${appDoc.path}/PasswordManager');
    if (!await dir.exists()) await dir.create(recursive: true);
    return dir.path;
  }

  Future<String> ensureEmptyOrPwdbSubdir(String folderPath) async {
    final dir = Directory(folderPath);
    if (!await dir.exists()) {
      await dir.create(recursive: true);
      return dir.path;
    }

    final contents = await dir.list(followLinks: false).toList();
    if (contents.isEmpty) {
      return dir.path;
    }

    final pwdbDir = Directory('${dir.path}/pwdb');
    if (!await pwdbDir.exists()) {
      await pwdbDir.create(recursive: true);
    }
    return pwdbDir.path;
  }

  Future<String> validateDbFolder(String folderPath) async {
    final metaFile = File('$folderPath/$metaFileName');
    if (await metaFile.exists()) return folderPath;

    final alt = Directory('$folderPath/pwdb');
    final altMeta = File('${alt.path}/$metaFileName');
    if (await altMeta.exists()) return alt.path;

    throw Exception('Invalid folder: missing $metaFileName');
  }

  Future<bool> isDirectoryEmpty(String path) async {
    final dir = Directory(path);
    if (!await dir.exists()) return true;
    try {
      return await dir.list(followLinks: false).isEmpty;
    } catch (_) {
      return true;
    }
  }

  Future<void> createEmptyDb({
    required String folderPath,
    required String password,
    int parts = 10,
    int memoryKb = 64, // return to 512 next time
    int iterations = 3,
    int parallelism = 2,
  }) async {
    if (password.isEmpty) throw ArgumentError('Password cannot be empty.');
    if (parts <= 0) throw ArgumentError('Parts must be > 0');

    folderPath = await ensureEmptyOrPwdbSubdir(folderPath);

    final salt = _secureRandomBytes(cryptoService.saltLength);

    final secretKey = await cryptoService.deriveKeyFromPassword(
      password: password,
      salt: salt,
      kdf: 'argon2id',
      iterations: iterations,
      memoryKb: memoryKb,
      parallelism: parallelism,
    );

    final initialJson = jsonEncode(<dynamic>[]);
    final encrypted = await cryptoService.encryptUtf8(secretKey, initialJson);
    _zeroBytes(Uint8List.fromList(utf8.encode(initialJson)));

    await _lock.synchronized(() async {
      await _writePartsAtomic(folderPath, encrypted, parts);

      final meta = {
        'version': 2,
        'kdf': 'argon2id',
        'memoryKb': memoryKb,
        'iterations': iterations,
        'parallelism': parallelism,
        'salt': base64Encode(salt),
        'cipher': cryptoService.cipherName,
        'nonceLength': cryptoService.nonceLength,
        'parts': parts,
        'fileBase': baseEncryptedName,
        'created': DateTime.now().toUtc().toIso8601String(),
      };

      final metaFile = File('$folderPath/$metaFileName');
      await metaFile.writeAsString(jsonEncode(meta), flush: true);
      await _storeDerivedKey(folderPath, secretKey);
    });
  }

  static Future<void> createEmptyDbIsolateEntry(List<dynamic> args) async {
    final SendPort sendPort = args[0];
    final String folderPath = args[1];
    final String password = args[2];
    final int parts = args[3];
    final int memoryKb = args[4];
    final int iterations = args[5];
    final int parallelism = args[6];

    final cryptoService = CryptoService();
    final storageService = StorageService(cryptoService);

    try {
      await storageService.createEmptyDb(
        folderPath: folderPath,
        password: password,
        parts: parts,
        memoryKb: memoryKb,
        iterations: iterations,
        parallelism: parallelism,
      );
      sendPort.send(null);
    } catch (e) {
      sendPort.send(e.toString());
    }
  }

  Future<({String plaintext, SecretKey key})> openDb({
    required String folderPath,
    required String password,
  }) async {
    final metaFile = File('$folderPath/$metaFileName');
    if (!await metaFile.exists()) {
      throw Exception('Meta file missing. Did you select the correct folder?');
    }

    return _lock.synchronized(() async {
      final meta =
          jsonDecode(await metaFile.readAsString()) as Map<String, dynamic>;

      final salt = base64Decode(meta['salt'] as String);
      final kdf = meta['kdf'] as String? ?? 'argon2id';
      final iterations = meta['iterations'] as int? ?? 3;
      final memoryKb = meta['memoryKb'] as int? ?? 524288;
      final parallelism = meta['parallelism'] as int? ?? 4;

      SecretKey secretKey;
      final derivedKeyFile = File('$folderPath/$derivedKeyFileName');

      if (await derivedKeyFile.exists()) {
        try {
          final raw = await derivedKeyFile.readAsBytes();
          secretKey = SecretKey(raw);
          final parts = meta['parts'] as int;
          final bytes = await _readAndConcatParts(folderPath, parts);
          await cryptoService.decryptUtf8(secretKey, bytes);
        } catch (_) {
          secretKey = await cryptoService.deriveKeyFromPassword(
            password: password,
            salt: salt,
            kdf: kdf,
            iterations: iterations,
            memoryKb: memoryKb,
            parallelism: parallelism,
          );
          await _storeDerivedKey(folderPath, secretKey);
        }
      } else {
        secretKey = await cryptoService.deriveKeyFromPassword(
          password: password,
          salt: salt,
          kdf: kdf,
          iterations: iterations,
          memoryKb: memoryKb,
          parallelism: parallelism,
        );
        await _storeDerivedKey(folderPath, secretKey);
      }

      final parts = meta['parts'] as int;
      final bytes = await _readAndConcatParts(folderPath, parts);
      final plaintext = await cryptoService.decryptUtf8(secretKey, bytes);
      return (plaintext: plaintext, key: secretKey);
    });
  }

  Future<void> _storeDerivedKey(String folderPath, SecretKey key) async {
    final raw = await key.extractBytes();
    final f = File('$folderPath/$derivedKeyFileName');
    await f.writeAsBytes(raw, flush: true);
  }

  Future<void> saveDb({
    required String folderPath,
    required SecretKey key,
    required String jsonDb,
  }) async {
    await _lock.synchronized(() async {
      final metaFile = File('$folderPath/$metaFileName');
      if (!await metaFile.exists()) throw Exception('Meta file missing.');

      final meta =
          jsonDecode(await metaFile.readAsString()) as Map<String, dynamic>;

      final parts = meta['parts'] as int;
      await _backupDb(folderPath, parts);

      final encrypted = await cryptoService.encryptUtf8(key, jsonDb);
      _zeroBytes(Uint8List.fromList(utf8.encode(jsonDb)));

      await _writePartsAtomic(folderPath, encrypted, parts);

      meta['modified'] = DateTime.now().toUtc().toIso8601String();
      await metaFile.writeAsString(jsonEncode(meta), flush: true);
    });
  }

  Future<void> _backupDb(String folderPath, int parts) async {
    for (var i = 0; i < parts; i++) {
      final file = File('$folderPath/$baseEncryptedName.part${i + 1}');
      if (await file.exists()) {
        final backupFile =
            File('$folderPath/$baseEncryptedName.part${i + 1}$backupSuffix');
        await file.copy(backupFile.path);
      }
    }
  }

  Future<void> deleteDerivedKey(String folderPath) async {
    try {
      final keyFile = File('$folderPath/$derivedKeyFileName');
      if (await keyFile.exists()) {
        await keyFile.delete();
      }
    } catch (e) {
      throw Exception('Failed to delete derived key: $e');
    }
  }

  Future<Uint8List> _readAndConcatParts(String folderPath, int parts) async {
    final buffer = <int>[];
    for (var i = 0; i < parts; i++) {
      final file = File('$folderPath/$baseEncryptedName.part${i + 1}');
      if (!await file.exists()) throw Exception('Missing part: ${file.path}');
      buffer.addAll(await file.readAsBytes());
    }
    return Uint8List.fromList(buffer);
  }

  Future<void> _writePartsAtomic(
      String folderPath, Uint8List data, int parts) async {
    final n = data.length;
    final partSize = (n / parts).ceil();
    for (var i = 0; i < parts; i++) {
      final start = i * partSize;
      final end = (start + partSize) > n ? n : (start + partSize);
      final slice = data.sublist(start, end);

      final tempFile = File('$folderPath/$baseEncryptedName.part${i + 1}.tmp');
      await tempFile.writeAsBytes(slice, flush: true);
      final finalFile = File('$folderPath/$baseEncryptedName.part${i + 1}');
      if (await finalFile.exists()) await finalFile.delete();
      await tempFile.rename(finalFile.path);
    }
  }

  List<int> _secureRandomBytes(int length) =>
      List<int>.generate(length, (_) => Random.secure().nextInt(256));

  void _zeroBytes(Uint8List bytes) {
    for (var i = 0; i < bytes.length; i++) bytes[i] = 0;
  }
}
