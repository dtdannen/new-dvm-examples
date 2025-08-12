# Encrypted Echo DVM Example - NIP-44 Gift Wrap

This example demonstrates how to implement end-to-end encryption for Data Vending Machines (DVMs) using the NIP-44 gift wrap specification. All job requests and responses are encrypted, ensuring complete privacy from relays and other users.

## 🔐 Key Concepts

### Gift Wrap Architecture
- **Gift Wrap (kind 1059)**: The outer encrypted envelope that only reveals the recipient's public key
- **Rumor (kind 1060)**: An inner unsigned event that contains the actual data, providing sender anonymity
- **Job Event (kind 25000)**: The actual DVM request/response, encrypted within the rumor

### Encryption Flow
1. **Client → DVM**:
   - Create job request (kind 25000)
   - Wrap in rumor (kind 1060)
   - Encrypt rumor with NIP-44
   - Wrap in gift wrap (kind 1059) with DVM's p-tag
   - Send to relay

2. **DVM → Client**:
   - Decrypt gift wrap
   - Extract rumor
   - Process job from rumor
   - Create result, wrap in rumor
   - Encrypt and send back as gift wrap

## 📁 Files

- `encrypted_echo_dvm.py` - The encrypted DVM server that processes requests
- `test_encrypted_dvm.py` - Test client for sending encrypted requests
- `.env` - Auto-generated file containing DVM keys

## 🚀 Running the Example

### 1. Start the Encrypted DVM

```bash
cd encrypted_dvms/echo_dvm_example
python encrypted_echo_dvm.py
```

On first run, this will:
- Generate a new DVM keypair
- Save keys to `.env` file
- Display the DVM's npub (share this with clients)
- Start listening for encrypted requests

### 2. Run the Test Client

In a new terminal:

```bash
cd encrypted_dvms/echo_dvm_example
python test_encrypted_dvm.py
```

This will:
- Generate a client keypair (or load from `CLIENT_SECRET_KEY` env var)
- Load the DVM's public key from `.env`
- Start an interactive session for sending encrypted messages

### Interactive Commands
- Type any message to send an encrypted echo request
- Type `status` to see pending requests
- Type `quit` to exit

### Single Test Mode

You can also send a single message:

```bash
python test_encrypted_dvm.py "Hello encrypted world!"
```

## 🔑 Key Management

### DVM Keys
- Automatically generated on first run
- Saved to `.env` file in the example directory
- Reused on subsequent runs

### Client Keys
- Generated fresh each run by default
- Can be persisted by setting `CLIENT_SECRET_KEY` environment variable:
  ```bash
  export CLIENT_SECRET_KEY=nsec1...
  python test_encrypted_dvm.py
  ```

## 🛡️ Privacy Features

1. **End-to-End Encryption**: Only the client and DVM can read the messages
2. **Sender Anonymity**: The rumor wrapper doesn't reveal the original author
3. **Minimal Metadata**: Only the recipient's public key is visible to relays
4. **No Open Requests**: All requests must be encrypted for a specific DVM

## 📊 Key Differences from Plaintext DVM

| Feature | Plaintext DVM | Encrypted DVM |
|---------|---------------|---------------|
| Event Kind | Direct kind 25000 | Wrapped in kind 1059 |
| Request Types | Open & Targeted | Targeted only |
| Subscription | Filter by category or p-tag | Filter by p-tag in gift wrap |
| Privacy | Public content | Fully encrypted |
| Discovery | Via category hashtag | Via public heartbeats |

## 🔍 Debugging

### Common Issues

1. **"No .env file found"**
   - Run the DVM first to generate keys

2. **"Failed to decrypt gift wrap"**
   - Ensure client and DVM are using correct keys
   - Check that the gift wrap is properly formatted

3. **No response received**
   - Verify DVM is running and connected to same relays
   - Check relay connectivity
   - Ensure proper p-tag filtering

### Monitoring

The implementation includes detailed logging:
- 🔐 Encryption/decryption steps
- 📋 Event extraction
- ✅ Successful operations
- ❌ Errors with details
- 💓 Heartbeats (public, for discovery)

## 📚 Technical Details

### NIP-44 Encryption
- Uses XChaCha20-Poly1305 authenticated encryption
- Creates shared secret between sender and recipient
- Version 2 of the NIP-44 specification

### Event Structure

```json
// Gift Wrap (kind 1059)
{
  "kind": 1059,
  "content": "<encrypted rumor>",
  "tags": [["p", "<recipient_pubkey>"]],
  "pubkey": "<sender_pubkey>",
  "sig": "..."
}

// Decrypted Rumor (kind 1060)
{
  "kind": 1060,
  "content": "<job event as JSON>",
  "created_at": 1234567890,
  "tags": []
}

// Inner Job Event (kind 25000)
{
  "kind": 25000,
  "content": "Job request/result",
  "tags": [
    ["i", "input data", "text/plain"],
    ["category", "echo"]
  ],
  "pubkey": "<original_author>",
  "sig": "..."
}
```

## 🔗 References

- [NIP-44: Encrypted Direct Messages](https://github.com/nostr-protocol/nips/blob/master/44.md)
- [NIP-59: Gift Wrap](https://github.com/nostr-protocol/nips/blob/master/59.md)
- [NIP-89: Data Vending Machines](https://github.com/nostr-protocol/nips/blob/master/89.md)

## 🎯 Use Cases

This encrypted DVM pattern is ideal for:
- Private computation services
- Confidential data processing
- Paid services requiring privacy
- Personal assistant DVMs
- Any DVM handling sensitive information

## 📈 Next Steps

To build on this example:
1. Add payment verification (using Lightning invoices)
2. Implement more complex job processing
3. Add job status updates (encrypted)
4. Create a mailer service for enhanced anonymity
5. Build specialized encrypted DVMs (translation, AI, etc.)
