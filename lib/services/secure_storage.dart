import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class SecureStorage {
  final FlutterSecureStorage? _storage;

  SecureStorage() : _storage = _maybeCreate();

  static FlutterSecureStorage? _maybeCreate() {
    try {
      if (kIsWeb) return null; // not needed here
      return const FlutterSecureStorage(
        aOptions: AndroidOptions(encryptedSharedPreferences: true),
        iOptions: IOSOptions(accessibility: KeychainAccessibility.first_unlock_this_device),
        mOptions: MacOsOptions(accessibility: KeychainAccessibility.first_unlock_this_device),
        lOptions: LinuxOptions(),
        wOptions: WindowsOptions(), // DPAPI
      );
    } catch (_) {
      return null;
    }
  }

  Future<bool> isAvailable() async {
    if (_storage == null) return false;
    try {
      await _storage!.containsKey(key: '__probe__');
      return true;
    } catch (_) {
      return false;
    }
  }

  Future<void> write(String key, List<int> value) async {
    if (_storage == null) throw const SecureStorageUnavailable();
    await _storage!.write(key: key, value: base64Encode(value));
  }

  Future<List<int>?> read(String key) async {
    if (_storage == null) throw const SecureStorageUnavailable();
    final v = await _storage!.read(key: key);
    if (v == null) return null;
    return base64Decode(v);
  }

  Future<void> delete(String key) async {
    if (_storage == null) throw const SecureStorageUnavailable();
    await _storage!.delete(key: key);
  }
}

class SecureStorageUnavailable implements Exception {
  const SecureStorageUnavailable();
  @override
  String toString() => 'SecureStorageUnavailable';
}
