import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'dart:math';
import 'dart:isolate';
import 'dart:async';
import 'package:cryptography/cryptography.dart';
import 'package:file_picker/file_picker.dart';
import 'package:path_provider/path_provider.dart';
import 'package:synchronized/synchronized.dart';
import 'crypto_service.dart';
import 'package:pointycastle/export.dart' as pc;
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class StorageService {
  final CryptoService cryptoService;
  StorageService(
    this.cryptoService, {
    this.useSecureStorage = true,
    FlutterSecureStorage? secureStorage,
  }) : _secureStorage = useSecureStorage ? (secureStorage ?? const FlutterSecureStorage()) : null;

  static const metaFileName = 'pwdb.meta.json';
  static const baseEncryptedName = 'pwdb.enc';
  static const backupSuffix = '.bak';
  static const derivedKeyFileName = 'derived.key';
  static const _verifierLabel = 'q-safe-verifier';
  static const _keyWrapLabel = 'qsv-keywrap-v1';
  static const _fastSigLabel = 'qsv-fastparams-v1';

  final _lock = Lock();

  
  static const int fastKdfSaltLen = 32;
  static const int fastMemoryKb = 131072;
  static const int fastIterations = 1;
  static const int fastParallelism = 2;

  static const int slowKdfIterations = 3;
  static const int slowKdfMemoryKb = 262144;
  static const int slowKdfParallelism = 2;

  final FlutterSecureStorage? _secureStorage;
  final bool useSecureStorage;

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

  
  
  Future<String?> pickVaultFolderForOpen() async {
    try {
      final res = await FilePicker.platform.pickFiles(
        dialogTitle: 'Open Vault - select pwdb.meta.json',
        type: FileType.custom,
        allowedExtensions: ['json'],
        allowMultiple: false,
      );
      final path = res?.files.single.path;
      if (path == null) return null;

      final name = path.split(Platform.pathSeparator).last;
      if (name != metaFileName) {
        throw Exception('Please select the file "$metaFileName".');
      }

      final folder = Directory(path).parent.path;
      
      if (!await File('$folder/$metaFileName').exists()) {
        throw Exception('Selected file is not a valid vault metadata file.');
      }
      return folder;
    } catch (e) {
      rethrow;
    }
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
    int parts = 3,
    int memoryKb = slowKdfMemoryKb,
    int iterations = slowKdfIterations,
    int parallelism = slowKdfParallelism,
  }) async {
    if (password.isEmpty) throw ArgumentError('Password cannot be empty.');
    if (password.length < 12) {
      throw ArgumentError('Password must be at least 12 characters.');
    }
    if (parts <= 0) throw ArgumentError('Parts must be > 0');

    folderPath = await ensureEmptyOrPwdbSubdir(folderPath);

    final salt = _secureRandomBytes(cryptoService.saltLength);

    // Strong/master key (slow profile).
    final strongKey = await cryptoService.deriveKeyFromPassword(
      password: password,
      salt: salt,
      kdf: 'argon2id',
      iterations: iterations,
      memoryKb: memoryKb,
      parallelism: parallelism,
    );

    final initialJson = jsonEncode(<dynamic>[]);
    final encrypted = await cryptoService.encryptUtf8(strongKey, initialJson);
    _zeroBytes(Uint8List.fromList(utf8.encode(initialJson)));

    // Fast unlock: derive fastKey and wrap master key.
    final fastSalt = _secureRandomBytes(fastKdfSaltLen);
    final fastKey = await _deriveFastKeyArgon2(
      password,
      fastSalt,
      memoryKb: fastMemoryKb,
      iterations: fastIterations,
      parallelism: fastParallelism,
    );
    final wrapped =
        await _wrapKeyWithAesGcm(fastKey, await strongKey.extractBytes());

    // Verifier for master key.
    final verifier = await _makeVerifier(strongKey);

    // Prepare meta with fast section in canonical key order (for HMAC).
    final fastMeta = <String, dynamic>{
      'kdf': 'argon2id',
      'iterations': fastIterations,
      'memoryKb': fastMemoryKb,
      'parallelism': fastParallelism,
      'salt': base64Encode(fastSalt),
    };

    // fastSig binds fast params to the master key.
    final fastSig = await _fastParamsSignature(strongKey, fastMeta);

    await _lock.synchronized(() async {
      await _writePartsAtomic(folderPath, encrypted, parts);

      final meta = {
        'version': 3,
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
        'verifier': base64Encode(verifier),
        'fast': fastMeta,
        'fastSig': base64Encode(fastSig),
      };

      final metaFile = File('$folderPath/$metaFileName');
      await _writeJsonAtomic(metaFile.path, jsonEncode(meta));

      await _storeWrappedDerivedKey(folderPath, wrapped);
    });

    _zeroBytes(Uint8List.fromList(await fastKey.extractBytes()));
  }

  static Future<void> createEmptyDbIsolateEntry(List<dynamic> args) async {
    final SendPort sendPort = args[0];
    final String folderPath = args[1];
    final String password = args[2];
    final int parts = args[3];
    final int memoryKb = args[4];
    final int iterations = args[5];
    final int parallelism = args[6];
    // args[7] may be present; ignored for backward compatibility.

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

      // Prefer OS secure storage; fallback to file if unavailable/missing.
      final wrappedFromSecure = await _readWrappedFromSecureStorage(folderPath);
      if (wrappedFromSecure != null) {
        final fastMeta = meta['fast'] as Map<String, dynamic>?;
        if (fastMeta == null) {
          throw Exception('Missing fast-unlock parameters in metadata.');
        }
        final kdfName = fastMeta['kdf'] as String? ?? 'argon2id';
        if (kdfName != 'argon2id') {
          throw Exception('Unsupported fast KDF: $kdfName');
        }
        final fastSalt = base64Decode(fastMeta['salt'] as String);
        final fIterations = fastMeta['iterations'] as int? ?? fastIterations;
        final fMemoryKb = fastMeta['memoryKb'] as int? ?? fastMemoryKb;
        final fParallelism = fastMeta['parallelism'] as int? ?? fastParallelism;

        final fastKey = await _deriveFastKeyArgon2(
          password,
          fastSalt,
          memoryKb: fMemoryKb,
          iterations: fIterations,
          parallelism: fParallelism,
        );
        try {
          final keyBytes = await _unwrapKeyWithAesGcm(fastKey, wrappedFromSecure);
          secretKey = SecretKey(keyBytes);
        } catch (_) {
          throw Exception('Invalid password or corrupted derived key.');
        } finally {
          _zeroBytes(Uint8List.fromList(await fastKey.extractBytes()));
        }

        // Verify fast params signature bound to master key.
        await _verifyFastParamsSignature(secretKey, meta);

        // Verify master key with verifier.
        final storedVerifierB64 = meta['verifier'] as String?;
        if (storedVerifierB64 == null) {
          throw Exception('Missing verifier.');
        }
        final storedVerifier = base64Decode(storedVerifierB64);
        final candidate = await _makeVerifier(secretKey);
        final ok = _constantTimeEquals(candidate, storedVerifier);
        _zeroBytes(candidate);
        if (!ok) throw Exception('Invalid password.');

        final parts = meta['parts'] as int;
        final bytes = await _readAndConcatParts(folderPath, parts);
        final plaintext = await cryptoService.decryptUtf8(secretKey, bytes);
        return (plaintext: plaintext, key: secretKey);
      }

      // Fallback file path (legacy / no secure storage).
      final derivedKeyFile = File('$folderPath/$derivedKeyFileName');
      if (await derivedKeyFile.exists()) {
        final wrapped = await derivedKeyFile.readAsBytes();
        final fastMeta = meta['fast'] as Map<String, dynamic>?;
        if (fastMeta == null) {
          throw Exception('Missing fast-unlock parameters in metadata.');
        }
        final kdfName = fastMeta['kdf'] as String? ?? 'argon2id';
        if (kdfName != 'argon2id') {
          throw Exception('Unsupported fast KDF: $kdfName');
        }
        final fastSalt = base64Decode(fastMeta['salt'] as String);
        final fIterations = fastMeta['iterations'] as int? ?? fastIterations;
        final fMemoryKb = fastMeta['memoryKb'] as int? ?? fastMemoryKb;
        final fParallelism = fastMeta['parallelism'] as int? ?? fastParallelism;

        final fastKey = await _deriveFastKeyArgon2(
          password,
          fastSalt,
          memoryKb: fMemoryKb,
          iterations: fIterations,
          parallelism: fParallelism,
        );
        try {
          final keyBytes = await _unwrapKeyWithAesGcm(fastKey, wrapped);
          secretKey = SecretKey(keyBytes);
        } catch (_) {
          throw Exception('Invalid password or corrupted derived key.');
        } finally {
          _zeroBytes(Uint8List.fromList(await fastKey.extractBytes()));
        }

        await _verifyFastParamsSignature(secretKey, meta);

        final storedVerifierB64 = meta['verifier'] as String?;
        if (storedVerifierB64 == null) {
          throw Exception('Missing verifier.');
        }
        final storedVerifier = base64Decode(storedVerifierB64);
        final candidate = await _makeVerifier(secretKey);
        final ok = _constantTimeEquals(candidate, storedVerifier);
        _zeroBytes(candidate);
        if (!ok) throw Exception('Invalid password.');

        final parts = meta['parts'] as int;
        final bytes = await _readAndConcatParts(folderPath, parts);
        final plaintext = await cryptoService.decryptUtf8(secretKey, bytes);
        return (plaintext: plaintext, key: secretKey);
      } else {
        // No wrapped key available; derive the slow way.
        secretKey = await cryptoService.deriveKeyFromPassword(
          password: password,
          salt: salt,
          kdf: kdf,
          iterations: iterations,
          memoryKb: memoryKb,
          parallelism: parallelism,
        );

        // Verifier
        final storedVerifierB64 = meta['verifier'] as String?;
        if (storedVerifierB64 == null) {
          throw Exception('Missing verifier.');
        }
        final storedVerifier = base64Decode(storedVerifierB64);
        final candidate = await _makeVerifier(secretKey);
        final ok = _constantTimeEquals(candidate, storedVerifier);
        _zeroBytes(candidate);
        if (!ok) throw Exception('Invalid password.');

        // Immediately create fast path artifacts
        final fastSalt = _secureRandomBytes(fastKdfSaltLen);
        final fastKey = await _deriveFastKeyArgon2(
          password,
          fastSalt,
          memoryKb: fastMemoryKb,
          iterations: fastIterations,
          parallelism: fastParallelism,
        );
        final wrapped =
            await _wrapKeyWithAesGcm(fastKey, await secretKey.extractBytes());
        await _storeWrappedDerivedKey(folderPath, wrapped);
        await _updateMetaFastInfo(
          folderPath,
          fastSalt,
          memoryKb: fastMemoryKb,
          iterations: fastIterations,
          parallelism: fastParallelism,
          strongKey: secretKey,
        );
        _zeroBytes(Uint8List.fromList(await fastKey.extractBytes()));

        final parts = meta['parts'] as int;
        final bytes = await _readAndConcatParts(folderPath, parts);
        final plaintext = await cryptoService.decryptUtf8(secretKey, bytes);
        return (plaintext: plaintext, key: secretKey);
      }
    });
  }

  Future<Uint8List> _makeVerifier(SecretKey key) async {
    final keyBytes = Uint8List.fromList(await key.extractBytes());
    final mac = pc.HMac(pc.SHA3Digest(512), 72);
    mac.init(pc.KeyParameter(keyBytes));
    final data = Uint8List.fromList(utf8.encode(_verifierLabel));
    mac.update(data, 0, data.length);
    final out = Uint8List(mac.macSize);
    mac.doFinal(out, 0);
    return out;
  }

  
  Future<SecretKey> _deriveFastKeyArgon2(
    String password,
    List<int> salt, {
    required int memoryKb,
    required int iterations,
    required int parallelism,
  }) async {
    return await cryptoService.deriveKeyFromPassword(
      password: password,
      salt: salt,
      kdf: 'argon2id',
      iterations: iterations,
      memoryKb: memoryKb,
      parallelism: parallelism,
    );
  }

  final AesGcm _aesGcm = AesGcm.with256bits();

  Future<Uint8List> _wrapKeyWithAesGcm(
      SecretKey wrappingKey, List<int> toWrap) async {
    final nonce = _secureRandomBytes(12);
    
    final labelBytes = utf8.encode(_keyWrapLabel);
    final msg = Uint8List(labelBytes.length + toWrap.length)
      ..setRange(0, labelBytes.length, labelBytes)
      ..setRange(labelBytes.length, labelBytes.length + toWrap.length, toWrap);

    final secretBox = await _aesGcm.encrypt(
      msg,
      secretKey: wrappingKey,
      nonce: Uint8List.fromList(nonce),
    );

    final blob = BytesBuilder();
    blob.add(nonce);
    blob.add(secretBox.cipherText);
    blob.add(secretBox.mac.bytes);
    return Uint8List.fromList(blob.toBytes());
  }

  Future<Uint8List> _unwrapKeyWithAesGcm(
      SecretKey wrappingKey, List<int> blob) async {
    if (blob.length < 12 + 16) throw Exception('Invalid wrapped blob.');
    final nonce = blob.sublist(0, 12);
    final macLen = 16;
    final macStart = blob.length - macLen;
    final cipherText = blob.sublist(12, macStart);
    final macBytes = blob.sublist(macStart);
    final secretBox = SecretBox(
      Uint8List.fromList(cipherText),
      nonce: Uint8List.fromList(nonce),
      mac: Mac(macBytes),
    );
    final plain = await _aesGcm.decrypt(secretBox, secretKey: wrappingKey);

    
    final labelBytes = utf8.encode(_keyWrapLabel);
    if (plain.length <= labelBytes.length) {
      throw Exception('Wrapped key payload too short.');
    }
    for (var i = 0; i < labelBytes.length; i++) {
      if (plain[i] != labelBytes[i]) {
        throw Exception('Wrapped key label mismatch.');
      }
    }
    final keyBytes = Uint8List.fromList(plain.sublist(labelBytes.length));
    
    _zeroBytes(plain);
    return keyBytes;
  }

  Future<void> _storeWrappedDerivedKey(
      String folderPath, Uint8List wrapped) async {
    // Try secure storage first.
    final ok = await _writeWrappedToSecureStorage(folderPath, wrapped);
    if (ok) return;

    // Fallback to file with restricted permissions.
    final f = File('$folderPath/$derivedKeyFileName');
    await f.writeAsBytes(wrapped, flush: true);
    await _restrictFilePermissions(f);
  }

  Future<void> _updateMetaFastInfo(
    String folderPath,
    List<int> fastSalt, {
    required int memoryKb,
    required int iterations,
    required int parallelism,
    SecretKey? strongKey,
  }) async {
    final metaFile = File('$folderPath/$metaFileName');
    if (!await metaFile.exists()) return;
    final meta =
        jsonDecode(await metaFile.readAsString()) as Map<String, dynamic>;
    final fastMeta = <String, dynamic>{
      'kdf': 'argon2id',
      'iterations': iterations,
      'memoryKb': memoryKb,
      'parallelism': parallelism,
      'salt': base64Encode(fastSalt),
    };
    meta['fast'] = fastMeta;

    // If we have the strong key, update the binding signature as well.
    if (strongKey != null) {
      final sig = await _fastParamsSignature(strongKey, fastMeta);
      meta['fastSig'] = base64Encode(sig);
    }

    await _writeJsonAtomic(metaFile.path, jsonEncode(meta));
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
      await _writeJsonAtomic(metaFile.path, jsonEncode(meta));
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

  Future<void> cleanupBackups(String folderPath) async {
    final dir = Directory(folderPath);
    if (!await dir.exists()) return;
    await for (final e in dir.list()) {
      if (e is File && e.path.endsWith(backupSuffix)) {
        try {
          await e.delete();
        } catch (_) {}
      }
    }
  }

  Future<void> deleteDerivedKey(String folderPath) async {
    try {
      // Prefer secure storage
      await _deleteWrappedFromSecureStorage(folderPath);
    } catch (_) {
      // ignore
    }
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

  
  Future<void> _writeJsonAtomic(String path, String json) async {
    final tmpPath = '$path.tmp';
    final tmp = File(tmpPath);
    await tmp.writeAsString(json, flush: true);
    final f = File(path);
    if (await f.exists()) await f.delete();
    await tmp.rename(path);
  }

  List<int> _secureRandomBytes(int length) =>
      List<int>.generate(length, (_) => Random.secure().nextInt(256));

  void _zeroBytes(List<int> bytes) {
    for (var i = 0; i < bytes.length; i++) bytes[i] = 0;
  }

  bool _constantTimeEquals(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= (a[i] ^ b[i]);
    }
    return diff == 0;
  }

  // ---- Secure storage helpers ----

  Future<bool> _writeWrappedToSecureStorage(String folderPath, Uint8List wrapped) async {
    if (_secureStorage == null) return false;
    try {
      final key = await _wrappedKeyName(folderPath);
      await _secureStorage!.write(key: key, value: base64Encode(wrapped));
      return true;
    } catch (_) {
      return false;
    }
  }

  Future<Uint8List?> _readWrappedFromSecureStorage(String folderPath) async {
    if (_secureStorage == null) return null;
    try {
      final key = await _wrappedKeyName(folderPath);
      final v = await _secureStorage!.read(key: key);
      if (v == null) return null;
      return Uint8List.fromList(base64Decode(v));
    } catch (_) {
      return null;
    }
  }

  Future<void> _deleteWrappedFromSecureStorage(String folderPath) async {
    if (_secureStorage == null) return;
    try {
      final key = await _wrappedKeyName(folderPath);
      await _secureStorage!.delete(key: key);
    } catch (_) {}
  }

  Future<String> _wrappedKeyName(String folderPath) async {
    final hasher = Sha256();
    final bytes = await hasher.hash(utf8.encode(folderPath));
    final hex = bytes.bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    return 'qsv_wrapped_$hex';
  }

  Future<void> _restrictFilePermissions(File f) async {
    if (Platform.isLinux || Platform.isMacOS) {
      try {
        await Process.run('chmod', ['600', f.path]);
      } catch (_) {}
    }
  }

  // ---- Fast params binding ----

  Future<Uint8List> _fastParamsSignature(SecretKey key, Map<String, dynamic> fastMeta) async {
    // Canonical payload: label || json(fastMeta) with fixed key order.
    final keyBytes = Uint8List.fromList(await key.extractBytes());
    final mac = pc.HMac(pc.SHA256Digest(), 64);
    mac.init(pc.KeyParameter(keyBytes));
    final payload = <int>[];
    payload.addAll(utf8.encode(_fastSigLabel));
    final canonical = jsonEncode({
      'kdf': fastMeta['kdf'],
      'iterations': fastMeta['iterations'],
      'memoryKb': fastMeta['memoryKb'],
      'parallelism': fastMeta['parallelism'],
      'salt': fastMeta['salt'],
    });
    final data = Uint8List.fromList(utf8.encode(canonical));
    mac.update(data, 0, data.length);
    final out = Uint8List(mac.macSize);
    mac.doFinal(out, 0);
    return out;
  }

  Future<void> _verifyFastParamsSignature(SecretKey strongKey, Map<String, dynamic> meta) async {
    final fastMeta = meta['fast'] as Map<String, dynamic>?;
    final sigB64 = meta['fastSig'] as String?;
    if (fastMeta == null || sigB64 == null) {
      throw Exception('Missing fast parameters or signature.');
    }
    final expected = await _fastParamsSignature(strongKey, fastMeta);
    final actual = base64Decode(sigB64);
    if (!_constantTimeEquals(expected, actual)) {
      throw Exception('Fast parameter integrity check failed.');
    }
  }

  // ---- Argon2 calibration (best-effort, bounded) ----

  Future<({int memoryKb, int iterations, int parallelism})> calibrateArgon2({
    int targetMs = 350,
    int minMemoryKb = 65536,   // 64 MiB
    int maxMemoryKb = 262144,  // 256 MiB
    int minIterations = 1,
    int maxIterations = 6,
    int parallelism = 2,
  }) async {
    // Use fixed memory, scale iterations until ~targetMs (bounded).
    final salt = _secureRandomBytes(16);
    final pw = base64Encode(_secureRandomBytes(16));

    int mem = minMemoryKb;
    int iters = minIterations;
    Duration last = Duration.zero;

    for (int i = minIterations; i <= maxIterations; i++) {
      final sw = Stopwatch()..start();
      await cryptoService.deriveKeyFromPassword(
        password: pw,
        salt: salt,
        kdf: 'argon2id',
        iterations: i,
        memoryKb: mem,
        parallelism: parallelism,
      );
      sw.stop();
      last = sw.elapsed;
      if (last.inMilliseconds >= targetMs) {
        iters = i;
        break;
      }
      iters = i;
    }

    // If way under target, consider increasing memory once (bounded).
    if (last.inMilliseconds < targetMs ~/ 2 && (mem * 2) <= maxMemoryKb) {
      mem *= 2;
    }

    return (memoryKb: mem, iterations: iters, parallelism: parallelism);
  }

  Future<({
    ({int memoryKb, int iterations, int parallelism}) slow,
    ({int memoryKb, int iterations, int parallelism}) fast,
  })> calibrateArgon2Profiles() async {
    final slow = await calibrateArgon2(
      targetMs: 350,
      minMemoryKb: 65536,
      maxMemoryKb: 262144,
      minIterations: 1,
      maxIterations: 6,
      parallelism: 2,
    );
    final fast = await calibrateArgon2(
      targetMs: 120,
      minMemoryKb: 65536,
      maxMemoryKb: 131072,
      minIterations: 1,
      maxIterations: 3,
      parallelism: 2,
    );
    return (slow: slow, fast: fast);
  }
}
