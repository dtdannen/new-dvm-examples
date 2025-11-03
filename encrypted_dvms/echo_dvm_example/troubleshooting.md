# Troubleshooting: Encrypted Echo DVM

This document tracks issues encountered while implementing the encrypted Echo DVM and the solutions attempted.

## Current Problem: DVM Not Receiving Encrypted Requests

### 📋 Issue Description
- **Date**: 2025-01-08
- **Status**: UNRESOLVED
- **Symptoms**:
  - Client successfully sends encrypted gift wrap events (kind 1059)
  - DVM is running and connected to relays
  - DVM subscription appears successful
  - DVM never receives/processes the encrypted requests
  - Client times out waiting for response

### 🔍 Diagnostic Information

#### Client Output (Working)
```
🔐 Sent encrypted job request
  Inner Job ID: feedc5f9... (for tracking)
  Gift Wrap ID: ba5288cc... (what relays see)

⏳ Waiting for encrypted response...
⚠️  No response received within 30 seconds
```

#### DVM Output (Not Receiving Events)
```
🔐 Subscribed to encrypted requests (kind 1059): SubscribeOutput(...)
Waiting for encrypted job requests...
💓 Sent heartbeat at 1755039766 (encrypted DVM)
```

### 🛠️ Solutions Attempted (DO NOT RETRY)

#### 1. ❌ Filter API Issues (RESOLVED)
- **Problem**: Used wrong filter methods
- **Tried**: 
  - `.p_tag()` method (doesn't exist)
  - `.pubkey()` for p-tag filtering (wrong usage)
- **Solution**: Used `.reference(f"p:{pubkey.to_hex()}")`
- **Status**: FIXED - This was not the root cause

#### 2. ❌ Subscribe API Issues (RESOLVED)
- **Problem**: Passed list to subscribe instead of single Filter
- **Tried**: `await self.client.subscribe([filter])`
- **Solution**: `await self.client.subscribe(filter)`
- **Status**: FIXED - This was not the root cause

#### 3. ❌ Event Signing Issues (RESOLVED)
- **Problem**: `send_event()` expected signed Event, got UnsignedEvent
- **Tried**: `build()` then `send_event()`
- **Solution**: Use `send_event_builder()` directly
- **Status**: FIXED - This was not the root cause

#### 4. ❌ Tag Creation Issues (RESOLVED)
- **Problem**: `Tag.p()` method doesn't exist
- **Tried**: `Tag.p(pubkey)`
- **Solution**: `Tag.parse(["p", pubkey.to_hex()])`
- **Status**: FIXED - This was not the root cause

### 🎯 Current Hypothesis

The issue is likely with the **p-tag filtering** in the subscription. The `.reference()` method may not work correctly for filtering gift wrap events by p-tags.

### 🔬 Next Steps to Try

#### Option A: Manual P-Tag Filtering
```python
# Subscribe to ALL gift wraps, filter manually
encrypted_filter = (Filter()
                  .kind(Kind(1059))
                  .since(Timestamp.now()))

# Then in handler:
if event.kind().as_u16() == 1059:
    # Check p-tags manually
    our_pubkey = self.keys.public_key().to_hex()
    for tag in event.tags().to_vec():
        tag_vec = tag.as_vec()
        if len(tag_vec) >= 2 and tag_vec[0] == "p" and tag_vec[1] == our_pubkey:
            # Process this event
```

#### Option B: Check Alternative P-Tag Filter Syntax
```python
# Try different p-tag filter formats:
.reference(f"#{self.keys.public_key().to_hex()}")  # Hash prefix?
.tags({"p": [self.keys.public_key().to_hex()]})    # Tags dict?
# Or check nostr-sdk documentation for correct p-tag filtering
```

#### Option C: Debug Event Reception
Add debug logging to see what events the DVM is actually receiving:
```python
async def handle(self, relay_url: str, subscription_id: str, event: Event):
    print(f"🔍 DEBUG: Received event kind {event.kind().as_u16()} from {relay_url}")
    print(f"   Event ID: {event.id().to_hex()[:8]}...")
    print(f"   Tags: {[tag.as_vec() for tag in event.tags().to_vec()]}")
    
    if event.kind().as_u16() == 1059:
        # Continue processing...
```

#### Option D: Verify Event Structure
Check if the client is creating gift wraps with the correct structure by logging:
```python
# In client, after creating gift wrap:
print(f"DEBUG: Gift wrap tags: {[tag.as_vec() for tag in gift_wrap_event.tags().to_vec()]}")
```

### 📊 Testing Matrix

| Test Case | Client Sends | DVM Receives | Status |
|-----------|-------------|--------------|---------|
| Manual p-tag filter | ❓ | ❓ | NOT TESTED |
| Debug logging | ❓ | ❓ | NOT TESTED |
| Alternative filter syntax | ❓ | ❓ | NOT TESTED |

### 🔧 Environment Details
- **Python nostr-sdk version**: (check with `pip show nostr-sdk`)
- **Relays tested**: wss://relay.damus.io, wss://nos.lol, wss://relay.primal.net
- **Event kinds**: 1059 (gift wrap), 1060 (rumor), 25000 (job)
- **Encryption**: NIP-44 v2

### 📝 Notes
- Both client and DVM connect successfully to relays
- Heartbeats from DVM are working (kind 11998)
- No error messages in either client or DVM
- Subscription IDs are returned successfully
- Issue appears to be specifically with gift wrap event filtering/delivery

---

## Previous Issues (RESOLVED)

### ✅ Import Issues
- **Problem**: Missing NIP-44 imports
- **Solution**: Added `nip44_encrypt, nip44_decrypt, Nip44Version` to imports

### ✅ Key Management
- **Problem**: Keys not persisted between runs  
- **Solution**: Auto-generate and save to `.env` file

### ✅ Event Builder API
- **Problem**: Incorrect usage of EventBuilder methods
- **Solution**: Use `.tags([...])` with list of Tag objects

---

*This document should be updated as new issues are discovered and solutions are tested.*
