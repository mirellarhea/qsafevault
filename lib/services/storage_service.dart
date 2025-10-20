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
import 'package:pointycastle/export.dart' as pc;
import 'package:crypto/crypto.dart' as crypto;
import 'package:qsafevault/services/secure_storage.dart';
import 'crypto_service.dart';

class StorageService {
  final CryptoService cryptoService;
  StorageService(this.cryptoService);

  static const metaFileName = 'pwdb.meta.json';
  static const baseEncryptedName = 'pwdb.enc';
  static const backupSuffix = '.bak';
  static const derivedKeyFileName = 'derived.key';
  static const _verifierLabel = 'q-safe-verifier';
  static const _keyWrapLabel = 'qsv-keywrap-v1';
  static const _fastSigLabel = 'qsv-fastparams-sig-v1'; 

  final _lock = Lock();

  static const int fastKdfSaltLen = 32;
  static const int fastMemoryKb = 131072;
  static const int fastIterations = 1;
  static const int fastParallelism = 2;

  static const int slowKdfIterations = 3;
  static const int slowKdfMemoryKb = 262144;
  static const int slowKdfParallelism = 2;

  
  static const int slowTargetMs = 400; 
  static const int fastTargetMs = 120; 
  static const int minIterations = 1;
  static const int minMemoryKb = 16384; 
  static const int minParallelism = 1;

  final SecureStorage _osSecure = SecureStorage();

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
    if (parts <= 0) throw ArgumentError('Parts must be > 0');

    folderPath = await ensureEmptyOrPwdbSubdir(folderPath);

    
    if (memoryKb <= 0 || iterations <= 0) {
      final tuned = await _calibrateArgon2(targetMs: slowTargetMs);
      memoryKb = max(tuned.memoryKb, minMemoryKb);
      iterations = max(tuned.iterations, minIterations);
      parallelism = max(tuned.parallelism, minParallelism);
    }

    final salt = _secureRandomBytes(cryptoService.saltLength);

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

    final fastSalt = _secureRandomBytes(fastKdfSaltLen);

    
    final fastTuned = await _calibrateArgon2(targetMs: fastTargetMs);
    final fIterations = max(fastTuned.iterations, minIterations);
    final fMemoryKb = max(fastTuned.memoryKb, minMemoryKb);
    final fParallelism = max(fastTuned.parallelism, minParallelism);

    final fastKey = await _deriveFastKeyArgon2(
      password,
      fastSalt,
      memoryKb: fMemoryKb,
      iterations: fIterations,
      parallelism: fParallelism,
    );
    final wrapped =
        await _wrapKeyWithAesGcm(fastKey, await strongKey.extractBytes());

    final verifier = await _makeVerifier(strongKey);

    
    final fastMeta = {
      'kdf': 'argon2id',
      'iterations': fIterations,
      'memoryKb': fMemoryKb,
      'parallelism': fParallelism,
      'salt': base64Encode(fastSalt),
    };
    final fastSig = await _signFastParams(strongKey, fastMeta);

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

      final wrappedFromSecure = await _tryReadWrappedFromSecure(folderPath);

      if (wrappedFromSecure != null || await File('$folderPath/$derivedKeyFileName').exists()) {
        final wrapped = wrappedFromSecure ??
            await File('$folderPath/$derivedKeyFileName').readAsBytes();

        final fastMeta = meta['fast'] as Map<String, dynamic>?;
        if (fastMeta == null) {
          throw Exception('Missing fast-unlock parameters in metadata.');
        }

        final kdfName = fastMeta['kdf'] as String? ?? 'argon2id';
        if (kdfName != 'argon2id') {
          throw Exception('Unsupported fast KDF: $kdfName');
        }
        final fastSalt = base64Decode(fastMeta['salt'] as String);
        final fIterations = (fastMeta['iterations'] as int?) ?? fastIterations;
        final fMemoryKb = (fastMeta['memoryKb'] as int?) ?? fastMemoryKb;
        final fParallelism = (fastMeta['parallelism'] as int?) ?? fastParallelism;

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

        
        final storedVerifierB64 = meta['verifier'] as String?;
        if (storedVerifierB64 == null) throw Exception('Missing verifier.');
        final storedVerifier = base64Decode(storedVerifierB64);
        final candidate = await _makeVerifier(secretKey);
        final ok = _constantTimeEquals(candidate, storedVerifier);
        _zeroBytes(candidate);
        if (!ok) throw Exception('Invalid password.');

        
        final fastSigB64 = meta['fastSig'] as String?;
        if (fastSigB64 != null) {
          final sig = base64Decode(fastSigB64);
          final expectSig = await _signFastParams(secretKey, fastMeta);
          final sigOk = _constantTimeEquals(sig, expectSig);
          if (!sigOk) {
            throw Exception('Fast KDF parameters tampered.');
          }
        }

        final partsCount = meta['parts'] as int;
        final bytes = await _readAndConcatParts(folderPath, partsCount);
        final plaintext = await cryptoService.decryptUtf8(secretKey, bytes);
        return (plaintext: plaintext, key: secretKey);
      } else {
        secretKey = await cryptoService.deriveKeyFromPassword(
          password: password,
          salt: salt,
          kdf: kdf,
          iterations: iterations,
          memoryKb: memoryKb,
          parallelism: parallelism,
        );

        final storedVerifierB64 = meta['verifier'] as String?;
        if (storedVerifierB64 == null) {
          throw Exception('Missing verifier.');
        }
        final storedVerifier = base64Decode(storedVerifierB64);
        final candidate = await _makeVerifier(secretKey);
        final ok = _constantTimeEquals(candidate, storedVerifier);
        _zeroBytes(candidate);
        if (!ok) throw Exception('Invalid password.');

        
        final fastSalt = _secureRandomBytes(fastKdfSaltLen);
        final tuned = await _calibrateArgon2(targetMs: fastTargetMs);
        final fIterations = max(tuned.iterations, minIterations);
        final fMemoryKb = max(tuned.memoryKb, minMemoryKb);
        final fParallelism = max(tuned.parallelism, minParallelism);
        final fastKey = await _deriveFastKeyArgon2(
          password,
          fastSalt,
          memoryKb: fMemoryKb,
          iterations: fIterations,
          parallelism: fParallelism,
        );
        final wrapped =
            await _wrapKeyWithAesGcm(fastKey, await secretKey.extractBytes());
        await _storeWrappedDerivedKey(folderPath, wrapped);
        await _updateMetaFastInfo(
          folderPath,
          fastSalt,
          memoryKb: fMemoryKb,
          iterations: fIterations,
          parallelism: fParallelism,
          masterKey: secretKey,
        );
        _zeroBytes(Uint8List.fromList(await fastKey.extractBytes()));

        final partsCount = meta['parts'] as int;
        final bytes = await _readAndConcatParts(folderPath, partsCount);
        final plaintext = await cryptoService.decryptUtf8(secretKey, bytes);
        return (plaintext: plaintext, key: secretKey);
      }
    });
  }

  
  Future<Uint8List> _signFastParams(SecretKey masterKey, Map<String, dynamic> fastMeta) async {
    final keyBytes = Uint8List.fromList(await masterKey.extractBytes());
    final mac = pc.HMac(pc.SHA3Digest(512), 128);
    mac.init(pc.KeyParameter(keyBytes));
    final canonical = _canonicalFastParamsString(fastMeta);
    final data = Uint8List.fromList(utf8.encode('$_fastSigLabel|$canonical'));
    mac.update(data, 0, data.length);
    final out = Uint8List(mac.macSize);
    mac.doFinal(out, 0);
    return out;
  }

  String _canonicalFastParamsString(Map<String, dynamic> m) {
    final kdf = (m['kdf'] as String?) ?? 'argon2id';
    final iterations = (m['iterations'] as int?) ?? 0;
    final memoryKb = (m['memoryKb'] as int?) ?? 0;
    final parallelism = (m['parallelism'] as int?) ?? 0;
    final salt = (m['salt'] as String?) ?? '';
    return 'k=$kdf;i=$iterations;m=$memoryKb;p=$parallelism;s=$salt';
  }

  Future<({int memoryKb, int iterations, int parallelism})> _calibrateArgon2({
    required int targetMs,
  }) async {
    
    final testSalt = _secureRandomBytes(cryptoService.saltLength);
    const testPassword = 'qsv-calibration';
    int iterations = max(minIterations, 1);
    int memoryKb = max(minMemoryKb, slowKdfMemoryKb ~/ 2);
    int parallelism = minParallelism;

    Duration took;
    do {
      final sw = Stopwatch()..start();
      await cryptoService.deriveKeyFromPassword(
        password: testPassword,
        salt: testSalt,
        kdf: 'argon2id',
        iterations: iterations,
        memoryKb: memoryKb,
        parallelism: parallelism,
      );
      sw.stop();
      took = sw.elapsed;
      if (took.inMilliseconds < targetMs) {
        iterations = (iterations * 2).clamp(minIterations, 1 << 24);
        if (iterations > 8 && took.inMilliseconds < targetMs / 4) {
          memoryKb = (memoryKb * 2).clamp(minMemoryKb, slowKdfMemoryKb);
        }
      }
    } while (took.inMilliseconds < targetMs && iterations < (1 << 20));
    return (memoryKb: memoryKb, iterations: iterations, parallelism: parallelism);
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

  Future<void> _storeWrappedDerivedKey(String folderPath, Uint8List wrapped) async {
    final keyId = _keyIdForFolder(folderPath);
    if (await _osSecure.isAvailable()) {
      try {
        await _osSecure.write(keyId, wrapped);
        
        final f = File('$folderPath/$derivedKeyFileName');
        if (await f.exists()) {
          await f.delete();
        }
        return;
      } catch (_) {
        
      }
    }
    final f = File('$folderPath/$derivedKeyFileName');
    await f.writeAsBytes(wrapped, flush: true);
    
    if (!Platform.isWindows) {
      try {
        await Process.run('chmod', ['600', f.path]);
      } catch (_) {}
    }
  }

  Future<Uint8List?> _tryReadWrappedFromSecure(String folderPath) async {
    if (await _osSecure.isAvailable()) {
      try {
        final v = await _osSecure.read(_keyIdForFolder(folderPath));
        if (v != null && v.isNotEmpty) return Uint8List.fromList(v);
      } catch (_) {}
    }
    return null;
  }

  String _keyIdForFolder(String folderPath) {
    final h = crypto.sha256.convert(utf8.encode(folderPath)).bytes;
    final b64 = base64UrlEncode(h);
    return 'qsv_wrapped_$b64';
  }

  Future<void> _updateMetaFastInfo(
    String folderPath,
    List<int> fastSalt, {
    required int memoryKb,
    required int iterations,
    required int parallelism,
    SecretKey? masterKey,
  }) async {
    final metaFile = File('$folderPath/$metaFileName');
    if (!await metaFile.exists()) return;
    final meta =
        jsonDecode(await metaFile.readAsString()) as Map<String, dynamic>;
    final fastMeta = {
      'kdf': 'argon2id',
      'iterations': iterations,
      'memoryKb': memoryKb,
      'parallelism': parallelism,
      'salt': base64Encode(fastSalt),
    };
    meta['fast'] = fastMeta;
    if (masterKey != null) {
      final sig = await _signFastParams(masterKey, fastMeta);
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
      
      await _cleanupOldBackups(folderPath, parts, keep: 2);
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

  Future<void> _cleanupOldBackups(String folderPath, int parts, {int keep = 2}) async {
    
    for (var i = 0; i < parts; i++) {
      final base = '$folderPath/$baseEncryptedName.part${i + 1}';
      final dir = Directory(folderPath);
      final backups = await dir
          .list()
          .where((e) => e is File && e.path.startsWith(base) && e.path.endsWith(backupSuffix))
          .cast<File>()
          .toList();
      backups.sort((a, b) => b.lastModifiedSync().compareTo(a.lastModifiedSync()));
      for (var j = keep; j < backups.length; j++) {
        try {
          await backups[j].delete();
        } catch (_) {}
      }
    }
  }

  Future<void> deleteDerivedKey(String folderPath) async {
    try {
      
      if (await _osSecure.isAvailable()) {
        try {
          await _osSecure.delete(_keyIdForFolder(folderPath));
        } catch (_) {}
      }
      
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
}
