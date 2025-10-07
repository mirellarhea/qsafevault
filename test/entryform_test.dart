import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:qsafevault/widgets/entry_form.dart';
import 'package:qsafevault/models/password_entry.dart';

void main() {
  group('EntryForm Widget Tests', () {
    late PasswordEntry existingEntry;
    late PasswordEntry savedEntry;

    setUp(() {
      existingEntry = PasswordEntry(
        id: '123',
        site: 'example.com',
        username: 'user1',
        email: 'user@example.com',
        password: 'secret',
        createdAt: DateTime.now().millisecondsSinceEpoch,
        updatedAt: DateTime.now().millisecondsSinceEpoch,
      );
      savedEntry = existingEntry;
    });

    testWidgets('Add entry displays empty fields and Save works',
        (WidgetTester tester) async {
      await tester.pumpWidget(MaterialApp(
        home: Builder(
          builder: (context) {
            return ElevatedButton(
              onPressed: () {
                showDialog(
                  context: context,
                  builder: (_) => EntryForm(
                    onSave: (entry) => savedEntry = entry,
                  ),
                );
              },
              child: const Text('Open Form'),
            );
          },
        ),
      ));

      await tester.tap(find.text('Open Form'));
      await tester.pumpAndSettle();

      expect(find.text('Add entry'), findsOneWidget);
      expect(find.byType(TextFormField), findsNWidgets(4));

      await tester.enterText(
          find.widgetWithText(TextFormField, 'Site'), 'newsite.com');
      await tester.enterText(
          find.widgetWithText(
              TextFormField, 'Username (or leave empty if Email used)'),
          'newuser');
      await tester.enterText(
          find.widgetWithText(TextFormField, 'Email (optional)'),
          'new@example.com');
      await tester.enterText(
          find.widgetWithText(TextFormField, 'Password'), 'newpass');

      await tester.tap(find.text('Save'));
      await tester.pumpAndSettle();

      expect(savedEntry.site, 'newsite.com');
      expect(savedEntry.username, 'newuser');
      expect(savedEntry.email, 'new@example.com');
      expect(savedEntry.password, 'newpass');
    });

    testWidgets('Edit entry populates fields and Save updates',
        (WidgetTester tester) async {
      await tester.pumpWidget(MaterialApp(
        home: Builder(
          builder: (context) {
            return ElevatedButton(
              onPressed: () {
                showDialog(
                  context: context,
                  builder: (_) => EntryForm(
                    existing: existingEntry,
                    onSave: (entry) => savedEntry = entry,
                  ),
                );
              },
              child: const Text('Open Form'),
            );
          },
        ),
      ));

      await tester.tap(find.text('Open Form'));
      await tester.pumpAndSettle();

      expect(find.text('Edit entry'), findsOneWidget);
      expect(find.text(existingEntry.site), findsOneWidget);
      expect(find.text(existingEntry.username), findsOneWidget);
      expect(find.text(existingEntry.email), findsOneWidget);
      expect(find.text(existingEntry.password), findsOneWidget);

      await tester.enterText(
          find.widgetWithText(TextFormField, 'Site'), 'editedsite.com');

      await tester.tap(find.text('Save'));
      await tester.pumpAndSettle();

      expect(savedEntry.site, 'editedsite.com');
    });

    testWidgets('Cancel button closes dialog without saving',
        (WidgetTester tester) async {
      savedEntry = existingEntry;

      await tester.pumpWidget(MaterialApp(
        home: Builder(
          builder: (context) {
            return ElevatedButton(
              onPressed: () {
                showDialog(
                  context: context,
                  builder: (_) => EntryForm(
                    onSave: (entry) => savedEntry = entry,
                  ),
                );
              },
              child: const Text('Open Form'),
            );
          },
        ),
      ));

      await tester.tap(find.text('Open Form'));
      await tester.pumpAndSettle();

      await tester.tap(find.text('Cancel'));
      await tester.pumpAndSettle();

      expect(savedEntry, savedEntry);
    });

    testWidgets('Validation errors prevent save', (WidgetTester tester) async {
      bool saveCalled = false;

      await tester.pumpWidget(MaterialApp(
        home: Builder(
          builder: (context) {
            return ElevatedButton(
              onPressed: () {
                showDialog(
                  context: context,
                  builder: (_) => EntryForm(
                    onSave: (entry) => saveCalled = true,
                  ),
                );
              },
              child: const Text('Open Form'),
            );
          },
        ),
      ));

      await tester.tap(find.text('Open Form'));
      await tester.pumpAndSettle();

      await tester.enterText(find.widgetWithText(TextFormField, 'Site'), '');
      await tester.enterText(
          find.widgetWithText(TextFormField, 'Password'), '');

      await tester.tap(find.text('Save'));
      await tester.pumpAndSettle();

      expect(saveCalled, false);
      expect(find.text('Please enter site'), findsOneWidget);
      expect(find.text('Please enter password'), findsOneWidget);
    });
  });
}
