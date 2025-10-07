import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:qsafevault/models/password_entry.dart';

void main() {
  group('PasswordEntry Model Tests', () {
    late PasswordEntry entry;

    setUp(() {
      entry = PasswordEntry(
        id: '123',
        site: 'example.com',
        username: 'user1',
        email: 'user@example.com',
        password: 'secret',
        createdAt: 1000,
        updatedAt: 2000,
      );
    });

    test('Constructor sets all fields correctly', () {
      expect(entry.id, '123');
      expect(entry.site, 'example.com');
      expect(entry.username, 'user1');
      expect(entry.email, 'user@example.com');
      expect(entry.password, 'secret');
      expect(entry.createdAt, 1000);
      expect(entry.updatedAt, 2000);
    });

    test('toJson returns correct map', () {
      final jsonMap = entry.toJson();
      expect(jsonMap['id'], '123');
      expect(jsonMap['site'], 'example.com');
      expect(jsonMap['username'], 'user1');
      expect(jsonMap['email'], 'user@example.com');
      expect(jsonMap['password'], 'secret');
      expect(jsonMap['createdAt'], 1000);
      expect(jsonMap['updatedAt'], 2000);
    });

    test('fromJson parses map correctly', () {
      final map = {
        'id': '999',
        'site': 'mysite.com',
        'username': 'user2',
        'email': 'u2@example.com',
        'password': 'pwd',
        'createdAt': 123,
        'updatedAt': 456,
      };
      final e = PasswordEntry.fromJson(map);
      expect(e.id, '999');
      expect(e.site, 'mysite.com');
      expect(e.username, 'user2');
      expect(e.email, 'u2@example.com');
      expect(e.password, 'pwd');
      expect(e.createdAt, 123);
      expect(e.updatedAt, 456);
    });

    test('fromJson handles missing optional fields', () {
      final map = {'id': '555'};
      final e = PasswordEntry.fromJson(map);
      expect(e.id, '555');
      expect(e.site, '');
      expect(e.username, '');
      expect(e.email, '');
      expect(e.password, '');
      expect(e.createdAt, isNonZero);
      expect(e.updatedAt, isNonZero);
    });

    test('listToJson and listFromJson work correctly', () {
      final list = [entry, entry];
      final jsonStr = PasswordEntry.listToJson(list);
      final decoded = json.decode(jsonStr) as List<dynamic>;
      expect(decoded.length, 2);

      final listFromJson = PasswordEntry.listFromJson(jsonStr);
      expect(listFromJson.length, 2);
      expect(listFromJson[0].id, entry.id);
      expect(listFromJson[1].id, entry.id);
    });

    test('Empty list serialization', () {
      final emptyList = <PasswordEntry>[];
      final jsonStr = PasswordEntry.listToJson(emptyList);
      expect(jsonStr, '[]');
      final listFromJson = PasswordEntry.listFromJson(jsonStr);
      expect(listFromJson, isEmpty);
    });
  });
}
