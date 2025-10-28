# Device Synchronization Example Usage

## Overview
This document provides examples of how to use the device synchronization feature in Q-Safe Vault.

## Basic Usage Flow

### Scenario: Syncing from Phone to Computer

#### On Computer (Receiving Device):
1. Open Q-Safe Vault and unlock your vault
2. Click the sync icon (⟳) in the top toolbar
3. Select "Receive from another device"
4. Note the PIN and IP address displayed (e.g., PIN: 123456, IP: 192.168.1.100)
5. Wait for the connection...

#### On Phone (Sending Device):
1. Open Q-Safe Vault and unlock your vault
2. Tap the sync icon (⟳) in the top toolbar
3. Select "Send to another device"
4. Enter the IP address from the computer: `192.168.1.100`
5. Enter the PIN from the computer: `123456`
6. Tap "Connect and Send"
7. Wait for sync to complete

#### After Sync:
- Both devices will have merged vault entries
- Any new entries are added
- Updated entries from the sender take precedence
- Don't forget to save on the receiving device!

## Security Best Practices

### Network Security
- ✅ Only sync on trusted networks (home WiFi, not public WiFi)
- ✅ Verify you're on the same local network
- ✅ Check that both devices show the same PIN before connecting
- ❌ Don't sync over public networks or untrusted WiFi
- ❌ Don't share your PIN with anyone

### PIN Verification
The 6-digit PIN is crucial for security:
- Generated randomly on the server device
- Used to verify the client is connecting to the right device
- Prevents man-in-the-middle attacks
- Only valid for 5 minutes

### Troubleshooting

#### "Connection timeout"
- Ensure both devices are on the same network
- Check firewall isn't blocking port 48923
- Verify the IP address is correct
- Make sure the receiving device is still waiting

#### "Invalid PIN"
- Double-check you entered the correct PIN
- The PIN is case-sensitive (all numbers)
- Try starting the sync process again

#### "Network error"
- Check WiFi is enabled on both devices
- Ensure they're connected to the same network
- Restart the sync process
- Try a different network if available

#### "Merge conflicts"
- The sync uses ID-based merging
- Newer entries (from sender) take precedence
- Check your entries after sync
- You can manually delete duplicates if needed

## Technical Details

### Encryption
- Key Exchange: X25519 (ECDH)
- Symmetric Encryption: AES-256-GCM
- PIN Hashing: HMAC-SHA256
- Nonce: Randomly generated per encryption

### Network
- Protocol: TCP
- Port: 48923
- Scope: Local network only
- Timeout: 5 minutes

### Data Transfer
- Format: JSON (encrypted)
- Max size: 100MB
- Compression: None (already encrypted)
- Integrity: Verified via AEAD MAC

## Privacy Notice

- No data is sent to the cloud or any server
- All communication is peer-to-peer
- Only the two syncing devices can decrypt the data
- The shared encryption key is ephemeral (never stored)
- After sync completes, the connection is closed

## Limitations

- Both devices must be online simultaneously
- Must be on the same local network
- Requires manual initiation on both devices
- No automatic background sync
- No conflict resolution UI (automatic merge only)

## Support

For issues or questions:
1. Check the main README.md
2. Review the troubleshooting section above
3. Open an issue on GitHub with:
   - Device types (e.g., Windows to Android)
   - Error messages
   - Network configuration
   - Steps to reproduce
