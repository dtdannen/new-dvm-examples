#!/usr/bin/env python3
"""
Test client for Encrypted Echo DVM - Sends encrypted job requests and receives encrypted responses

This client demonstrates how to communicate with a DVM using NIP-44 gift wrap encryption.
All messages are end-to-end encrypted, ensuring complete privacy.

The encryption process:
1. Client creates a job request
2. Wraps it in a rumor (unsigned event)
3. Encrypts the rumor using the DVM's public key
4. Sends it wrapped in a gift wrap event
5. Receives encrypted responses the same way

Only the client and DVM can read the messages - relays and other users see only encrypted data.
"""

import asyncio
import os
import sys
import json
from typing import Optional, Dict
from nostr_sdk import (
    Client, Keys, EventBuilder, Filter, Kind, Tag, Timestamp, 
    Event, HandleNotification, RelayMessage, NostrSigner, RelayUrl, PublicKey,
    nip44_encrypt, nip44_decrypt, Nip44Version
)

class EncryptedDVMTestClient:
    """
    Test client for sending encrypted job requests to DVMs using NIP-44 gift wrap
    """
    
    def __init__(self, keys: Keys, relay_urls: list, dvm_npub: str):
        self.keys = keys
        self.relay_urls = relay_urls
        self.client = None
        self.dvm_npub = dvm_npub
        self.dvm_pubkey = None
        
        # Track pending encrypted jobs by their INNER job ID
        self.waiting_for_response = {}
        
        print(f"🔐 Encrypted Test Client")
        print(f"Client Public Key: {self.keys.public_key().to_bech32()}")
        
        # Parse DVM public key
        try:
            self.dvm_pubkey = PublicKey.parse(dvm_npub)
            print(f"Target DVM: {dvm_npub[:16]}...")
            print(f"✅ All messages will be encrypted for this DVM")
        except Exception as e:
            print(f"❌ Error parsing DVM npub: {e}")
            raise
    
    async def initialize(self):
        """Initialize the client and connect to relays"""
        signer = NostrSigner.keys(self.keys)
        self.client = Client(signer)
        
        # Add relays
        for relay_url in self.relay_urls:
            relay = RelayUrl.parse(relay_url)
            await self.client.add_relay(relay)
            print(f"Added relay: {relay_url}")
        
        # Connect to relays
        await self.client.connect()
        print("Connected to relays")
        
        # Subscribe to encrypted responses
        await self.subscribe_to_encrypted_responses()
    
    async def subscribe_to_encrypted_responses(self):
        """
        Subscribe to encrypted gift wrap events (kind 1059) addressed to us.
        
        The DVM will send responses as gift wraps with our pubkey in the p-tag.
        Only we can decrypt these messages.
        """
        
        # Filter for gift wraps with our pubkey in p-tag
        # Using reference() to filter for p-tags pointing to us
        encrypted_filter = (Filter()
                          .kind(Kind(1059))  # Gift wrap events
                          .reference(f"p:{self.keys.public_key().to_hex()}")  # Filter for p-tag with our pubkey
                          .since(Timestamp.now()))
        
        subscription_id = await self.client.subscribe(encrypted_filter)
        print(f"🔐 Subscribed to encrypted responses (kind 1059): {subscription_id}")
    
    async def create_encrypted_job_request(self, input_text: str) -> tuple[Event, Event]:
        """
        Create an encrypted job request using NIP-44 gift wrap.
        
        This demonstrates the full encryption pipeline:
        1. Create the actual job request (kind 25000)
        2. Wrap it in a rumor (kind 1060) for anonymity
        3. Encrypt the rumor using NIP-44
        4. Wrap everything in a gift wrap (kind 1059)
        
        Returns: (inner_job_event, gift_wrap_event)
        """
        
        print(f"\n📝 Creating encrypted job request for: '{input_text}'")
        
        # Step 1: Create the inner job request event (kind 25000)
        # This is what the DVM will actually process
        job_tags = [
            Tag.parse(["i", input_text, "text/plain"]),  # Input data
            Tag.parse(["category", "echo"]),             # Service category (for DVM's reference)
        ]
        
        job_event_builder = EventBuilder(
            kind=Kind(25000), 
            content=f"Encrypted job request: {input_text}"
        )
        job_event_builder = job_event_builder.tags(job_tags)
        inner_job_event = job_event_builder.build(self.keys.public_key())
        
        print(f"  1️⃣ Created job event: {inner_job_event.id().to_hex()[:8]}...")
        
        # Step 2: Create a rumor (kind 1060) containing the job event
        # Rumors are unsigned events that provide sender anonymity
        rumor = {
            "kind": 1060,  # Rumor event kind
            "content": inner_job_event.as_json(),  # The job event as JSON
            "created_at": Timestamp.now().as_secs(),
            "tags": []  # Rumors typically don't have tags
        }
        rumor_json = json.dumps(rumor)
        
        print(f"  2️⃣ Wrapped in rumor (kind 1060)")
        
        # Step 3: Encrypt the rumor using NIP-44
        # This creates a shared secret between us and the DVM
        encrypted_payload = nip44_encrypt(
            self.keys.secret_key(),     # Our private key
            self.dvm_pubkey,            # DVM's public key
            rumor_json,                 # The rumor as JSON
            Nip44Version.V2            # NIP-44 version 2
        )
        
        print(f"  3️⃣ Encrypted with NIP-44 (payload size: {len(encrypted_payload)} bytes)")
        
        # Step 4: Create the gift wrap (kind 1059)
        # This is the outer envelope that only reveals the recipient
        gift_wrap_builder = EventBuilder(
            kind=Kind(1059),
            content=encrypted_payload  # The encrypted rumor
        )
        
        # Add p-tag to indicate the recipient (this is the ONLY public info)
        gift_wrap_builder = gift_wrap_builder.tags([Tag.parse(["p", self.dvm_pubkey.to_hex()])])
        
        # Build the gift wrap event (unsigned for now, will be signed when sending)
        # We need to return the builder to send it properly
        print(f"  4️⃣ Created gift wrap")
        print(f"  🎁 Ready to send encrypted request")
        
        return inner_job_event, gift_wrap_builder
    
    async def send_encrypted_job_request(self, input_text: str) -> Event:
        """
        Send an encrypted job request to the DVM.
        
        Returns the inner job event (for tracking purposes).
        """
        
        # Create the encrypted request
        inner_job_event, gift_wrap_builder = await self.create_encrypted_job_request(input_text)
        
        # Send the gift wrap event using send_event_builder which handles signing
        await self.client.send_event_builder(gift_wrap_builder)
        
        # Build the event to get its ID (for display purposes)
        gift_wrap_event = gift_wrap_builder.build(self.keys.public_key())
        
        # Track the INNER job ID for response matching
        job_id = inner_job_event.id().to_hex()
        self.waiting_for_response[job_id] = {
            "input": input_text,
            "timestamp": asyncio.get_event_loop().time(),
            "completed": False,
            "gift_wrap_id": gift_wrap_event.id().to_hex()
        }
        
        print(f"🔐 Sent encrypted job request")
        print(f"  Inner Job ID: {job_id[:8]}... (for tracking)")
        print(f"  Gift Wrap ID: {gift_wrap_event.id().to_hex()[:8]}... (what relays see)")
        print()
        
        return inner_job_event
    
    def decrypt_gift_wrap_response(self, gift_wrap_event: Event) -> Optional[Event]:
        """
        Decrypt a gift wrap response from the DVM.
        
        This reverses the encryption process:
        1. Decrypt the gift wrap to get the rumor
        2. Extract the result event from the rumor
        3. Return the actual result event
        """
        
        try:
            # Step 1: Decrypt the gift wrap content
            encrypted_content = gift_wrap_event.content()
            sender_pubkey = gift_wrap_event.author()
            
            # Decrypt using NIP-44
            decrypted = nip44_decrypt(
                self.keys.secret_key(),  # Our private key
                sender_pubkey,            # Sender's public key (should be DVM)
                encrypted_content         # The encrypted payload
            )
            
            print(f"  🔓 Decrypted gift wrap from {sender_pubkey.to_bech32()[:16]}...")
            
            # Step 2: Parse the decrypted rumor
            rumor_data = json.loads(decrypted)
            
            # Verify it's a rumor
            if rumor_data.get('kind') != 1060:
                print(f"  ⚠️ Expected rumor (1060), got kind {rumor_data.get('kind')}")
                return None
            
            # Step 3: Extract the result event from the rumor's content
            result_event_json = rumor_data.get('content', '')
            if not result_event_json:
                print("  ⚠️ Rumor has no content")
                return None
            
            # Parse the result event
            result_event = Event.from_json(result_event_json)
            
            # Verify it's a result (kind 25000)
            if result_event.kind().as_u16() != 25000:
                print(f"  ⚠️ Expected result (25000), got kind {result_event.kind().as_u16()}")
                return None
            
            print(f"  📋 Extracted result event: {result_event.id().to_hex()[:8]}...")
            return result_event
            
        except Exception as e:
            print(f"  ❌ Failed to decrypt response: {e}")
            return None
    
    def extract_referenced_event(self, event: Event) -> Optional[str]:
        """Extract the event ID that this event is referencing (from e-tag)"""
        for tag in event.tags().to_vec():
            tag_vec = tag.as_vec()
            if len(tag_vec) >= 2 and tag_vec[0] == "e":
                return tag_vec[1]
        return None
    
    def get_status_from_event(self, event: Event) -> str:
        """Extract status from event tags"""
        for tag in event.tags().to_vec():
            tag_vec = tag.as_vec()
            if len(tag_vec) >= 2 and tag_vec[0] == "status":
                return tag_vec[1]
        return "unknown"
    
    async def handle_encrypted_response(self, gift_wrap_event: Event):
        """
        Handle an encrypted response from the DVM.
        
        This decrypts the response and matches it to our pending requests.
        """
        
        print(f"\n=== 🔐 Encrypted Response Received ===")
        print(f"Gift Wrap ID: {gift_wrap_event.id().to_hex()[:8]}...")
        
        # Decrypt the gift wrap to get the actual response
        result_event = self.decrypt_gift_wrap_response(gift_wrap_event)
        if not result_event:
            print("Failed to decrypt response")
            return
        
        # Check which request this is responding to
        referenced_event_id = self.extract_referenced_event(result_event)
        if not referenced_event_id:
            print("  ⚠️ Response doesn't reference any request")
            return
        
        if referenced_event_id not in self.waiting_for_response:
            print(f"  ⚠️ Response references unknown request: {referenced_event_id[:8]}...")
            return
        
        # Get the original request info
        request_info = self.waiting_for_response[referenced_event_id]
        if request_info["completed"]:
            print("  ℹ️ Already handled this response")
            return
        
        request_info["completed"] = True
        
        # Extract response details
        status = self.get_status_from_event(result_event)
        response_content = result_event.content()
        dvm_pubkey = result_event.author().to_bech32()
        
        # Calculate response time
        response_time = asyncio.get_event_loop().time() - request_info["timestamp"]
        
        print(f"Request ID: {referenced_event_id[:8]}...")
        print(f"Original Input: '{request_info['input']}'")
        print(f"DVM Response: '{response_content}'")
        print(f"Status: {status}")
        print(f"DVM: {dvm_pubkey[:16]}...")
        print(f"Response Time: {response_time:.2f} seconds")
        print("=" * 40 + "\n")
    
    async def run_interactive_test(self):
        """Run interactive test session with the encrypted DVM"""
        if not self.client:
            await self.initialize()
        
        print("\n" + "=" * 60)
        print("🔐 Encrypted Echo DVM Test Client")
        print("=" * 60)
        print()
        print("This client sends ENCRYPTED requests to the DVM.")
        print("All communication is protected with NIP-44 encryption.")
        print()
        print("Commands:")
        print("  - Type your message to send to the Echo DVM")
        print("  - Type 'quit' to exit")
        print("  - Type 'status' to see pending requests")
        print()
        
        # Create notification handler for encrypted responses
        class NotificationHandler(HandleNotification):
            def __init__(self, test_client):
                self.test_client = test_client
                self.response_received = asyncio.Event()

            async def handle(self, relay_url: str, subscription_id: str, event: Event):
                # Only process gift wrap events (kind 1059)
                # The filter already ensures we only get events with our p-tag
                if event.kind().as_u16() == 1059:
                    await self.test_client.handle_encrypted_response(event)
                    self.response_received.set()

            async def handle_msg(self, relay_url: str, msg: RelayMessage):
                # Handle relay messages if needed
                pass
        
        handler = NotificationHandler(self)
        
        # Start the notification handler
        notification_task = asyncio.create_task(
            self.client.handle_notifications(handler)
        )
        
        try:
            while True:
                try:
                    # Get input from user
                    user_input = input("Enter message (or 'quit'/'status'): ").strip()
                    
                    if user_input.lower() == 'quit':
                        break
                    elif user_input.lower() == 'status':
                        pending = [req for req in self.waiting_for_response.values() 
                                 if not req["completed"]]
                        print(f"📊 Pending requests: {len(pending)}")
                        for req in pending:
                            print(f"  - '{req['input']}' (waiting {asyncio.get_event_loop().time() - req['timestamp']:.1f}s)")
                        continue
                    elif not user_input:
                        continue
                    
                    # Reset the response event
                    handler.response_received.clear()
                    
                    # Send encrypted job request
                    await self.send_encrypted_job_request(user_input)
                    
                    # Show waiting message and wait for response
                    print("⏳ Waiting for encrypted response...")
                    
                    try:
                        # Wait for response with timeout
                        await asyncio.wait_for(handler.response_received.wait(), timeout=30.0)
                        print("✅ Response received! Ready for next input.\n")
                    except asyncio.TimeoutError:
                        print("⚠️  No response received within 30 seconds")
                        print("The DVM might be offline or the message may have been lost.\n")
                    
                except KeyboardInterrupt:
                    print("\n⚠️  Interrupted by user")
                    break
                except Exception as e:
                    print(f"❌ Error: {e}")
        
        finally:
            notification_task.cancel()
            print("\n🔐 Shutting down encrypted test client...")

def load_dvm_pubkey():
    """
    Load DVM public key from .env file in the encrypted example directory
    """
    from pathlib import Path
    
    # Look for .env in the encrypted example directory
    env_file = Path(__file__).parent / ".env"
    if not env_file.exists():
        print("❌ No .env file found in encrypted_dvms/echo_dvm_example/")
        print("Please run the encrypted_echo_dvm.py first to generate keys.")
        return None
    
    with open(env_file, 'r') as f:
        for line in f:
            if line.strip().startswith("DVM_NPUB="):
                npub = line.strip().split("=", 1)[1].strip('"\'')
                return npub
    
    print("❌ DVM_NPUB not found in .env file")
    return None

async def main():
    """Main function to run the encrypted test client"""
    
    print("=" * 60)
    print("🔐 ENCRYPTED ECHO DVM TEST CLIENT")
    print("=" * 60)
    print()
    print("This client demonstrates NIP-44 encrypted communication")
    print("with a Data Vending Machine (DVM).")
    print()
    
    # Generate client keys (or load from environment)
    client_nsec = os.getenv("CLIENT_SECRET_KEY")
    if client_nsec:
        try:
            client_keys = Keys.parse(client_nsec)
            print("🔑 Loaded client keys from environment")
        except Exception as e:
            print(f"⚠️  Failed to parse CLIENT_SECRET_KEY: {e}")
            print("Generating new client keys...")
            client_keys = Keys.generate()
    else:
        client_keys = Keys.generate()
        print(f"🔑 Generated new client keys")
        print(f"   Client nsec: {client_keys.secret_key().to_bech32()}")
        print(f"   (Set CLIENT_SECRET_KEY env var to reuse these keys)")
    
    # Load DVM public key from .env file
    dvm_npub = load_dvm_pubkey()
    if not dvm_npub:
        print("\n❌ Cannot proceed without DVM public key")
        print("Please run encrypted_echo_dvm.py first to generate the DVM keys.")
        return
    
    print(f"\n🎯 Target DVM: {dvm_npub[:16]}...")
    
    # Same relays as the DVM
    relay_urls = [
        "wss://relay.damus.io",
        "wss://nos.lol",
        "wss://relay.primal.net"
    ]
    
    # Create encrypted test client
    client = EncryptedDVMTestClient(client_keys, relay_urls, dvm_npub)
    
    # Check for command line arguments for single test mode
    if len(sys.argv) > 1:
        # Single test mode - send one message and exit
        message = " ".join(sys.argv[1:])
        print(f"\n📤 Single test mode: '{message}'")
        
        await client.initialize()
        
        # Send the encrypted message
        await client.send_encrypted_job_request(message)
        
        # Wait for response
        print("⏳ Waiting for response (10 second timeout)...")
        
        # Simple wait for response
        await asyncio.sleep(10)
        print("\n✅ Test complete")
    else:
        # Interactive mode
        await client.run_interactive_test()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
