import 'package:flutter/material.dart';
import '/models/password_entry.dart';
import 'package:uuid/uuid.dart';
class EntryForm extends StatefulWidget {
  final PasswordEntry? existing;
  final void Function(PasswordEntry) onSave;
  const EntryForm({Key? key, this.existing, required this.onSave})
      : super(key: key);
  @override
  State<EntryForm> createState() => _EntryFormState();
}
class _EntryFormState extends State<EntryForm> {
  final _formKey = GlobalKey<FormState>();
  final _siteCtl = TextEditingController();
  final _userCtl = TextEditingController();
  final _emailCtl = TextEditingController();
  final _passCtl = TextEditingController();
  @override
  void initState() {
    super.initState();
    if (widget.existing != null) {
      _siteCtl.text = widget.existing!.site;
      _userCtl.text = widget.existing!.username;
      _emailCtl.text = widget.existing!.email;
      _passCtl.text = widget.existing!.password;
    }
  }
  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: Text(widget.existing == null ? 'Add entry' : 'Edit entry'),
      content: Form(
        key: _formKey,
        child: SingleChildScrollView(
          child: Column(
            children: [
              TextFormField(
                controller: _siteCtl,
                decoration: InputDecoration(labelText: 'Site'),
                validator: (v) =>
                    (v == null || v.isEmpty) ? 'Please enter site' : null,
              ),
              TextFormField(
                controller: _userCtl,
                decoration: InputDecoration(
                    labelText: 'Username (or leave empty if Email used)'),
              ),
              TextFormField(
                controller: _emailCtl,
                decoration: InputDecoration(labelText: 'Email (optional)'),
              ),
              TextFormField(
                controller: _passCtl,
                decoration: InputDecoration(labelText: 'Password'),
                obscureText: true,
                validator: (v) =>
                    (v == null || v.isEmpty) ? 'Please enter password' : null,
              ),
            ],
          ),
        ),
      ),
      actions: [
        TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('Cancel')),
        ElevatedButton(
            onPressed: () {
              if (_formKey.currentState?.validate() ?? false) {
                final id = widget.existing?.id ?? Uuid().v4();
                final now = DateTime.now().millisecondsSinceEpoch;
                final entry = PasswordEntry(
                  id: id,
                  site: _siteCtl.text.trim(),
                  username: _userCtl.text.trim(),
                  email: _emailCtl.text.trim(),
                  password: _passCtl.text,
                  createdAt: widget.existing?.createdAt ?? now,
                  updatedAt: now,
                );
                widget.onSave(entry);
                Navigator.of(context).pop();
              }
            },
            child: const Text('Save')),
      ],
    );
  }
}
