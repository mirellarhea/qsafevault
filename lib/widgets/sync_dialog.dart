import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '/services/sync_service.dart';

/// Dialog for device synchronization
class SyncDialog extends StatefulWidget {
  final Function(String vaultJson) onReceiveData;
  final String currentVaultJson;
  
  const SyncDialog({
    Key? key,
    required this.onReceiveData,
    required this.currentVaultJson,
  }) : super(key: key);
  
  @override
  State<SyncDialog> createState() => _SyncDialogState();
}

class _SyncDialogState extends State<SyncDialog> {
  final SyncService _syncService = SyncService();
  SyncSession? _session;
  bool _isServer = false;
  bool _isClient = false;
  String _status = 'Choose sync mode';
  String? _pin;
  List<String> _addresses = [];
  final _addressController = TextEditingController();
  final _pinController = TextEditingController();
  String? _errorMessage;
  
  @override
  void dispose() {
    _syncService.stop();
    _addressController.dispose();
    _pinController.dispose();
    super.dispose();
  }
  
  Future<void> _startAsServer() async {
    setState(() {
      _isServer = true;
      _status = 'Starting server...';
      _errorMessage = null;
    });
    
    try {
      _syncService.events?.listen((event) {
        if (!mounted) return;
        
        if (event is ServerStartedEvent) {
          setState(() {
            _pin = event.pin;
            _addresses = event.addresses;
            _status = 'Waiting for connection...';
          });
        } else if (event is HandshakeCompleteEvent) {
          setState(() {
            _status = 'Connected! Waiting for data...';
          });
        } else if (event is DataReceivedEvent) {
          setState(() {
            _status = 'Data received successfully!';
          });
        } else if (event is ErrorEvent) {
          setState(() {
            _errorMessage = event.message;
            _status = 'Error';
          });
        }
      });
      
      _session = await _syncService.startServer();
      
      // Receive vault data
      final vaultJson = await _syncService.receiveVaultData(_session!);
      
      if (mounted) {
        widget.onReceiveData(vaultJson);
        Navigator.of(context).pop();
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Vault synced successfully!')),
        );
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _errorMessage = e.toString();
          _status = 'Error';
        });
      }
    }
  }
  
  Future<void> _connectAsClient() async {
    if (_addressController.text.isEmpty || _pinController.text.isEmpty) {
      setState(() {
        _errorMessage = 'Please enter address and PIN';
      });
      return;
    }
    
    setState(() {
      _isClient = true;
      _status = 'Connecting...';
      _errorMessage = null;
    });
    
    try {
      _syncService.events?.listen((event) {
        if (!mounted) return;
        
        if (event is ConnectedEvent) {
          setState(() {
            _status = 'Performing handshake...';
          });
        } else if (event is HandshakeCompleteEvent) {
          setState(() {
            _status = 'Sending vault data...';
          });
        } else if (event is DataSentEvent) {
          setState(() {
            _status = 'Data sent successfully!';
          });
        } else if (event is ErrorEvent) {
          setState(() {
            _errorMessage = event.message;
            _status = 'Error';
          });
        }
      });
      
      _session = await _syncService.connectToServer(
        address: _addressController.text.trim(),
        pin: _pinController.text.trim(),
      );
      
      // Send vault data
      await _syncService.sendVaultData(_session!, widget.currentVaultJson);
      
      if (mounted) {
        await Future.delayed(const Duration(seconds: 1));
        Navigator.of(context).pop();
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Vault synced successfully!')),
        );
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _errorMessage = e.toString();
          _status = 'Error';
        });
      }
    }
  }
  
  Widget _buildInitialChoice() {
    return Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const Text(
          'Device Synchronization',
          style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
          textAlign: TextAlign.center,
        ),
        const SizedBox(height: 16),
        const Text(
          'Choose your sync mode:',
          style: TextStyle(fontSize: 16),
        ),
        const SizedBox(height: 24),
        ElevatedButton.icon(
          icon: const Icon(Icons.cloud_download),
          label: const Text('Receive from another device'),
          onPressed: _startAsServer,
          style: ElevatedButton.styleFrom(
            padding: const EdgeInsets.all(16),
          ),
        ),
        const SizedBox(height: 12),
        OutlinedButton.icon(
          icon: const Icon(Icons.cloud_upload),
          label: const Text('Send to another device'),
          onPressed: () {
            setState(() {
              _isClient = true;
            });
          },
          style: OutlinedButton.styleFrom(
            padding: const EdgeInsets.all(16),
          ),
        ),
        const SizedBox(height: 16),
        const Divider(),
        const SizedBox(height: 8),
        const Text(
          '⚠️ Security Notice',
          style: TextStyle(fontWeight: FontWeight.bold, color: Colors.orange),
        ),
        const SizedBox(height: 8),
        const Text(
          'Both devices must be on the same local network. '
          'The connection is encrypted end-to-end. '
          'Verify the PIN matches on both devices.',
          style: TextStyle(fontSize: 12, color: Colors.grey),
        ),
      ],
    );
  }
  
  Widget _buildServerView() {
    return Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const Text(
          'Waiting for Connection',
          style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
          textAlign: TextAlign.center,
        ),
        const SizedBox(height: 16),
        Text(
          _status,
          style: const TextStyle(fontSize: 16),
          textAlign: TextAlign.center,
        ),
        const SizedBox(height: 24),
        if (_pin != null) ...[
          const Text(
            'Verification PIN:',
            style: TextStyle(fontSize: 14, fontWeight: FontWeight.bold),
          ),
          const SizedBox(height: 8),
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: Colors.blue.withOpacity(0.1),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: Colors.blue),
            ),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Text(
                  _pin!,
                  style: const TextStyle(
                    fontSize: 32,
                    fontWeight: FontWeight.bold,
                    letterSpacing: 8,
                    fontFamily: 'monospace',
                  ),
                ),
                const SizedBox(width: 16),
                IconButton(
                  icon: const Icon(Icons.copy),
                  onPressed: () {
                    Clipboard.setData(ClipboardData(text: _pin!));
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(content: Text('PIN copied')),
                    );
                  },
                ),
              ],
            ),
          ),
          const SizedBox(height: 16),
          const Text(
            'Your IP addresses:',
            style: TextStyle(fontSize: 14, fontWeight: FontWeight.bold),
          ),
          const SizedBox(height: 8),
          ..._addresses.map((addr) => Container(
            margin: const EdgeInsets.only(bottom: 8),
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: Colors.green.withOpacity(0.1),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: Colors.green),
            ),
            child: Row(
              children: [
                Expanded(
                  child: Text(
                    addr,
                    style: const TextStyle(
                      fontSize: 16,
                      fontFamily: 'monospace',
                    ),
                  ),
                ),
                IconButton(
                  icon: const Icon(Icons.copy),
                  onPressed: () {
                    Clipboard.setData(ClipboardData(text: addr));
                    ScaffoldMessenger.of(context).showSnackBar(
                      SnackBar(content: Text('IP address copied: $addr')),
                    );
                  },
                ),
              ],
            ),
          )),
          const SizedBox(height: 16),
          const Text(
            'Enter this PIN and one of the IP addresses on the sending device.',
            style: TextStyle(fontSize: 12, color: Colors.grey),
            textAlign: TextAlign.center,
          ),
        ] else ...[
          const Center(child: CircularProgressIndicator()),
        ],
        if (_errorMessage != null) ...[
          const SizedBox(height: 16),
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: Colors.red.withOpacity(0.1),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: Colors.red),
            ),
            child: Text(
              'Error: $_errorMessage',
              style: const TextStyle(color: Colors.red),
            ),
          ),
        ],
        const SizedBox(height: 16),
        OutlinedButton(
          onPressed: () {
            _syncService.stop();
            Navigator.of(context).pop();
          },
          child: const Text('Cancel'),
        ),
      ],
    );
  }
  
  Widget _buildClientView() {
    return Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const Text(
          'Send Vault to Device',
          style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
          textAlign: TextAlign.center,
        ),
        const SizedBox(height: 16),
        Text(
          _status,
          style: const TextStyle(fontSize: 16),
          textAlign: TextAlign.center,
        ),
        const SizedBox(height: 24),
        if (_session == null) ...[
          TextField(
            controller: _addressController,
            decoration: const InputDecoration(
              labelText: 'IP Address',
              hintText: '192.168.1.100',
              border: OutlineInputBorder(),
              prefixIcon: Icon(Icons.computer),
            ),
            keyboardType: TextInputType.number,
          ),
          const SizedBox(height: 16),
          TextField(
            controller: _pinController,
            decoration: const InputDecoration(
              labelText: 'Verification PIN',
              hintText: '123456',
              border: OutlineInputBorder(),
              prefixIcon: Icon(Icons.pin),
            ),
            keyboardType: TextInputType.number,
            maxLength: 6,
          ),
          const SizedBox(height: 16),
          const Text(
            'Enter the IP address and PIN shown on the receiving device.',
            style: TextStyle(fontSize: 12, color: Colors.grey),
          ),
          const SizedBox(height: 16),
          ElevatedButton(
            onPressed: _connectAsClient,
            style: ElevatedButton.styleFrom(
              padding: const EdgeInsets.all(16),
            ),
            child: const Text('Connect and Send'),
          ),
        ] else ...[
          const Center(child: CircularProgressIndicator()),
        ],
        if (_errorMessage != null) ...[
          const SizedBox(height: 16),
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: Colors.red.withOpacity(0.1),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: Colors.red),
            ),
            child: Text(
              'Error: $_errorMessage',
              style: const TextStyle(color: Colors.red),
            ),
          ),
        ],
        const SizedBox(height: 16),
        OutlinedButton(
          onPressed: () {
            if (_session == null) {
              setState(() {
                _isClient = false;
              });
            } else {
              _syncService.stop();
              Navigator.of(context).pop();
            }
          },
          child: Text(_session == null ? 'Back' : 'Cancel'),
        ),
      ],
    );
  }
  
  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      content: SingleChildScrollView(
        child: SizedBox(
          width: MediaQuery.of(context).size.width * 0.8,
          child: _isServer
              ? _buildServerView()
              : _isClient
                  ? _buildClientView()
                  : _buildInitialChoice(),
        ),
      ),
    );
  }
}
