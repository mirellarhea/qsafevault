import 'dart:async';
import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:qsafevault/services/sync_service.dart';

void main() {
  group('SyncService', () {
    late SyncService serverService;
    late SyncService clientService;

    setUp(() {
      serverService = SyncService();
      clientService = SyncService();
    });

    tearDown(() async {
      await serverService.stop();
      await clientService.stop();
    });

    test('should generate 6-digit PIN', () async {
      final completer = Completer<String>();
      
      serverService.events?.listen((event) {
        if (event is ServerStartedEvent) {
          completer.complete(event.pin);
        }
      });

      // Start server (don't await, just trigger it)
      serverService.startServer();
      
      final pin = await completer.future.timeout(
        const Duration(seconds: 5),
        onTimeout: () => '',
      );

      expect(pin.length, equals(6));
      expect(int.tryParse(pin), isNotNull);
      
      await serverService.stop();
    });

    test('should start server and get local IP addresses', () async {
      final completer = Completer<List<String>>();
      
      serverService.events?.listen((event) {
        if (event is ServerStartedEvent) {
          completer.complete(event.addresses);
        }
      });

      // Start server
      serverService.startServer();
      
      final addresses = await completer.future.timeout(
        const Duration(seconds: 5),
        onTimeout: () => <String>[],
      );

      expect(addresses, isNotEmpty);
      
      await serverService.stop();
    });

    test('should fail connection with wrong PIN', () async {
      String? pin;
      String? address;
      
      final serverCompleter = Completer<void>();
      serverService.events?.listen((event) {
        if (event is ServerStartedEvent) {
          pin = event.pin;
          address = event.addresses.isNotEmpty ? event.addresses.first : null;
          serverCompleter.complete();
        }
      });

      // Start server
      serverService.startServer();
      await serverCompleter.future.timeout(const Duration(seconds: 5));
      
      if (address == null) {
        await serverService.stop();
        return; // Skip test if no network available
      }

      // Try to connect with wrong PIN
      bool errorOccurred = false;
      clientService.events?.listen((event) {
        if (event is ErrorEvent) {
          errorOccurred = true;
        }
      });

      try {
        await clientService.connectToServer(
          address: address!,
          pin: '000000', // Wrong PIN
        );
      } catch (e) {
        errorOccurred = true;
      }

      // Wait a bit for error to propagate
      await Future.delayed(const Duration(milliseconds: 500));
      
      expect(errorOccurred, isTrue);
      
      await serverService.stop();
      await clientService.stop();
    });

    test('should have idle status initially', () {
      expect(serverService.status, equals(SyncStatus.idle));
      expect(clientService.status, equals(SyncStatus.idle));
    });

    test('should cleanup on stop', () async {
      final completer = Completer<void>();
      
      serverService.events?.listen((event) {
        if (event is ServerStartedEvent) {
          completer.complete();
        }
      });

      serverService.startServer();
      await completer.future.timeout(const Duration(seconds: 5));
      
      await serverService.stop();
      
      expect(serverService.status, equals(SyncStatus.idle));
    });

    test('SyncEvent types should be created correctly', () {
      final serverStarted = SyncEvent.serverStarted(
        pin: '123456',
        addresses: ['192.168.1.1'],
      );
      expect(serverStarted, isA<ServerStartedEvent>());
      expect((serverStarted as ServerStartedEvent).pin, equals('123456'));
      expect(serverStarted.addresses, equals(['192.168.1.1']));

      final connected = SyncEvent.connected();
      expect(connected, isA<ConnectedEvent>());

      final handshake = SyncEvent.handshakeComplete();
      expect(handshake, isA<HandshakeCompleteEvent>());

      final dataSent = SyncEvent.dataSent();
      expect(dataSent, isA<DataSentEvent>());

      final dataReceived = SyncEvent.dataReceived();
      expect(dataReceived, isA<DataReceivedEvent>());

      final error = SyncEvent.error('Test error');
      expect(error, isA<ErrorEvent>());
      expect((error as ErrorEvent).message, equals('Test error'));
    });

    test('should reject connection when already in progress', () async {
      final completer = Completer<void>();
      
      serverService.events?.listen((event) {
        if (event is ServerStartedEvent) {
          completer.complete();
        }
      });

      serverService.startServer();
      await completer.future.timeout(const Duration(seconds: 5));
      
      // Try to start server again
      expect(
        () => serverService.startServer(),
        throwsStateError,
      );
      
      await serverService.stop();
    });
  });

  group('PasswordEntry Sync Merge', () {
    test('should merge entries by ID', () {
      final entriesJson1 = json.encode([
        {
          'id': '1',
          'site': 'example.com',
          'username': 'user1',
          'email': 'user@example.com',
          'password': 'pass1',
          'createdAt': 1000,
          'updatedAt': 1000,
        },
        {
          'id': '2',
          'site': 'test.com',
          'username': 'user2',
          'email': 'user@test.com',
          'password': 'pass2',
          'createdAt': 2000,
          'updatedAt': 2000,
        },
      ]);

      final entriesJson2 = json.encode([
        {
          'id': '1',
          'site': 'example.com',
          'username': 'user1_updated',
          'email': 'user@example.com',
          'password': 'pass1_updated',
          'createdAt': 1000,
          'updatedAt': 3000,
        },
        {
          'id': '3',
          'site': 'newsite.com',
          'username': 'user3',
          'email': 'user@newsite.com',
          'password': 'pass3',
          'createdAt': 4000,
          'updatedAt': 4000,
        },
      ]);

      final entries1 = (json.decode(entriesJson1) as List)
          .map((e) => e as Map<String, dynamic>)
          .toList();
      final entries2 = (json.decode(entriesJson2) as List)
          .map((e) => e as Map<String, dynamic>)
          .toList();

      // Simulate merge
      final merged = <String, Map<String, dynamic>>{};
      for (final entry in entries1) {
        merged[entry['id'] as String] = entry;
      }
      for (final entry in entries2) {
        merged[entry['id'] as String] = entry;
      }

      expect(merged.length, equals(3)); // Should have 3 unique entries
      expect(merged['1']!['username'], equals('user1_updated')); // Updated
      expect(merged.containsKey('2'), isTrue); // Original entry kept
      expect(merged.containsKey('3'), isTrue); // New entry added
    });
  });
}
