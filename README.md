# new-dvm-examples
Example Code that Accompanies Articles on Making Simpler DVMs

## Echo DVM - Simple Nostr Data Vending Machine

A simple implementation of a Nostr Data Vending Machine (DVM) that echoes back whatever input it receives. This serves as a basic example of how to build DVMs using the new simplified approach with rust-nostr Python bindings.

## What is a DVM?

Data Vending Machines are APIs on Nostr - computational services that anyone can offer without needing domain names or IP addresses. Users send job requests as Nostr events, and DVMs respond with results using the same decentralized network.

## Features

- **Simple Echo Service**: Returns whatever text you send it
- **Modern DVM Architecture**: Uses the new simplified event kinds (25000 for both requests and responses)
- **Heartbeat Monitoring**: Sends regular heartbeat events (kind 11998) every 10 seconds for service health monitoring
- **Persistent Identity**: Automatically saves and reuses DVM keys across sessions using `.env` file
- **Category-Based Discovery**: Uses "echo" category for easy discovery
- **Robust Error Handling**: Handles duplicates, errors, and edge cases
- **Easy Testing**: Includes interactive test client with real-time heartbeat display

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Install Dependencies

```bash
pip install nostr-sdk
```

## Quick Start

### 1. Run the Echo DVM

```bash
python echo_dvm.py
```

The DVM will start and display:
```
Initializing Echo DVM
Category: echo
DVM Public Key: npub1...
Added relay: wss://relay.damus.io
Added relay: wss://nos.lol
Added relay: wss://relay.primal.net
Connected to relays
Subscribed to job requests for category 'echo': ...

Echo DVM is now running and listening for job requests...
Press Ctrl+C to stop
```

### 2. Test the DVM

In another terminal, run the test client:

```bash
python test_dvm.py
```

**Interactive Mode:**
```
=== Echo DVM Test Client ===
Type your message to send to the Echo DVM
Type 'quit' to exit
Type 'status' to see pending requests

Enter message: Hello World
Sent job request: a1b2c3d4
Input: 'Hello World'
Open request for category: echo

=== Response Received ===
Request ID: a1b2c3d4
Original Input: 'Hello World'
DVM Response: 'Echo: Hello World'
Status: success
DVM: npub1dvm...
Response Time: 0.15 seconds
========================

Enter message: quit
Test client shutting down...
```

**Single Message Mode:**
```bash
python test_dvm.py "Hello, Echo DVM!"
```

## Architecture

### Event Types Used

| Kind  | Description | Usage |
|-------|-------------|-------|
| 25000 | Job Requests/Responses | Both requests and responses use this kind |
| 11998 | Heartbeat Events | Service health monitoring - sent every 10 seconds |
| 31999 | DVM Announcements | Service discovery (not implemented in this example) |

### How It Works

1. **DVM Subscription**: The Echo DVM subscribes to kind 25000 events tagged with category "echo"
2. **Job Request**: Test client sends a kind 25000 event with input text and category tag
3. **Processing**: DVM receives the request, processes it (echoes the input), and creates a response
4. **Response**: DVM sends back a kind 25000 event that tags the original request
5. **Client Receives**: Test client identifies responses by the "e" tag referencing its original request

### Key Innovation

Unlike traditional APIs, both requests and responses use the same event kind (25000). Responses are identified by:
- Having an "e" tag that references the original request event ID
- Coming from a different pubkey (the DVM's pubkey)
- Including a "status" tag indicating success/error

## Configuration

### Environment Variables

```bash
# Optional: Set specific keys to reuse them across sessions
export DVM_SECRET_KEY="nsec1your_dvm_secret_key_here"
export CLIENT_SECRET_KEY="nsec1your_client_secret_key_here"

# Optional: Target a specific DVM by its public key
export TARGET_DVM_NPUB="npub1your_target_dvm_public_key_here"
```

### Default Relays

The DVM connects to these relays by default:
- `wss://relay.damus.io`
- `wss://nos.lol`
- `wss://relay.primal.net`

You can modify the `relay_urls` list in the code to use different relays.

## File Structure

```
.
├── echo_dvm.py      # Main DVM implementation
├── test_dvm.py      # Test client for sending requests
└── README.md        # This documentation
```

## Code Overview

### Echo DVM (`echo_dvm.py`)

**Key Components:**
- `EchoDVM` class: Main DVM implementation
- `initialize()`: Connects to relays and sets up subscriptions
- `process_job_request()`: Core business logic (echo functionality)
- `send_job_result()`: Sends responses back to clients
- `handle_job_request()`: Main request processing pipeline

**Core Logic:**
```python
async def process_job_request(self, event: Event) -> Optional[str]:
    """Process echo job - just return the input"""
    input_data = self.extract_input_from_event(event)
    if not input_data:
        return None
    
    print(f"Echoing: {input_data}")
    return f"Echo: {input_data}"
```

### Test Client (`test_dvm.py`)

**Key Components:**
- `DVMTestClient` class: Test client implementation
- `send_job_request()`: Creates and sends job requests
- `handle_response()`: Processes DVM responses
- `run_interactive_test()`: Interactive testing mode

## Extending the DVM

To create your own DVM service, modify the `process_job_request()` method:

```python
async def process_job_request(self, event: Event) -> Optional[str]:
    """Replace this with your computational service"""
    input_data = self.extract_input_from_event(event)
    params = self.extract_job_params(event)
    
    # Your custom logic here
    result = your_custom_function(input_data, params)
    
    return result
```

Example modifications:
- **Translation DVM**: Translate text between languages
- **AI Image Generator**: Generate images from text prompts
- **Text Summarizer**: Summarize long articles
- **Code Formatter**: Format and beautify code

## Event Format Examples

### Job Request (Kind 25000)
```json
{
  "kind": 25000,
  "content": "Job request: Hello World",
  "tags": [
    ["i", "Hello World", "text/plain"],
    ["category", "echo"],
    ["t", "echo"]
  ]
}
```

### Job Response (Kind 25000)
```json
{
  "kind": 25000,
  "content": "Echo: Hello World", 
  "tags": [
    ["e", "original_request_event_id"],
    ["p", "requester_pubkey"],
    ["category", "echo"],
    ["status", "success"]
  ]
}
```

## Troubleshooting

### DVM Not Receiving Requests
- Check that both DVM and client are connected to the same relays
- Verify the DVM is subscribed to the correct category
- Ensure events are being published successfully

### No Response from DVM
- Check DVM logs for error messages
- Verify the request format includes required tags
- Make sure the DVM is running and connected

### Connection Issues
- Try different relays if some are down
- Check your internet connection
- Some relays may have rate limits

## Development

### Running in Development
```bash
# Terminal 1: Run DVM with debug output
python echo_dvm.py

# Terminal 2: Send test requests
python test_dvm.py "test message"
```

### Adding Logging
You can add more detailed logging by importing the logging module:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Next Steps

This Echo DVM demonstrates the basics of DVM implementation. For production use, consider:

1. **Add DVM Announcements**: Implement kind 31999 announcement events
2. **Add Heartbeat Events**: Use kind 31998 for service health monitoring  
3. **Implement Payment**: Add Lightning integration for paid services
4. **Add Encryption**: Implement NIP-44 encryption for sensitive data
5. **Error Handling**: More robust error handling and retry logic
6. **Monitoring**: Add metrics and health checks
7. **Deployment**: Containerization and production deployment

## Resources

- [Nostr Protocol](https://nostr.com)
- [NIP-90: Data Vending Machines](https://github.com/nostr-protocol/nips/blob/master/90.md)
- [rust-nostr Documentation](https://rust-nostr.org)
- [DVM Marketplace](https://dvmdash.live)

## Contributing

Feel free to submit issues and pull requests to improve this example DVM implementation.

## License

This project is released into the public domain. Use it however you like!
