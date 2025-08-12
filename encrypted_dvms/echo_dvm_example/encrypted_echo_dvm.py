#!/usr/bin/env python3
"""
Encrypted Echo DVM - Returns whatever input it receives, using NIP-44 gift wrap encryption

This DVM demonstrates how to implement end-to-end encryption for Data Vending Machines
using the NIP-44 gift wrap specification. All job requests and responses are encrypted,
ensuring that only the intended recipient can read the content.

Key Concepts:
- Gift Wrap (kind 1059): The outer encrypted envelope that hides everything except the recipient
- Rumor (kind 1060): An inner unsigned event that contains the actual data
- NIP-44 Encryption: Modern encryption standard for Nostr using XChaCha20-Poly1305

The encryption flow:
1. Job Request (kind 25000) → wrapped in Rumor (1060) → encrypted → wrapped in Gift Wrap (1059)
2. Only the recipient's public key is visible in the gift wrap's p-tag
3. The relay and other users cannot see the content or its specific metadata. The sender of
   the wrapper IS visible, but this can be a third-party 'mailer' service to protect the
   original author's identity.
"""

import asyncio
import os
import json
from typing import Dict, List, Optional
from nostr_sdk import (
    Client, Keys, EventBuilder, Filter, Kind, Tag, Timestamp, 
    Event, HandleNotification, RelayMessage, NostrSigner, RelayUrl,
    nip44_encrypt, nip44_decrypt, Nip44Version, PublicKey
)

class EncryptedEchoDVM:
    """
    Encrypted DVM that echoes back whatever input it receives.
    All communication is encrypted using NIP-44 gift wrap.
    """
    
    def __init__(self, 
                 keys: Keys, 
                 relay_urls: List[str],
                 dvm_name: str = "Encrypted Echo DVM"):
        self.keys = keys
        self.relay_urls = relay_urls
        self.dvm_name = dvm_name
        self.client = None
        
        # Track processed jobs to avoid duplicates
        self.processed_jobs = set()
        
        print(f"Initializing {dvm_name}")
        print(f"DVM Public Key: {self.keys.public_key().to_bech32()}")
        print("🔐 This DVM only accepts encrypted requests (NIP-44 gift wrap)")
    
    async def initialize(self):
        """Initialize the Nostr client and connect to relays"""
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
        
        # Subscribe to encrypted job requests
        await self.subscribe_to_encrypted_requests()
    
    async def subscribe_to_encrypted_requests(self):
        """
        Subscribe to encrypted gift wrap events (kind 1059) addressed to us.
        
        In the encrypted model, we ONLY receive targeted requests - there are no
        "open" requests since encryption requires knowing the recipient's public key.
        """
        
        # Filter for ALL gift wraps (kind 1059) - we'll filter by p-tag in the handler
        # This is because reference() filtering might not work reliably for gift wraps
        encrypted_filter = (Filter()
                          .kind(Kind(1059))  # Gift wrap events
                          .since(Timestamp.now()))
        
        subscription = await self.client.subscribe(encrypted_filter)
        print(f"🔐 Subscribed to ALL gift wraps (kind 1059): {subscription}")
        print("Will filter for our p-tag in the event handler...")
        print("Waiting for encrypted job requests...")
    
    def decrypt_gift_wrap(self, gift_wrap_event: Event) -> Optional[str]:
        """
        Decrypt a gift wrap event using NIP-44.
        
        The gift wrap contains encrypted content that only we can decrypt using:
        - Our private key
        - The sender's public key (from the gift wrap's author field)
        
        Returns the decrypted JSON string or None if decryption fails.
        """
        try:
            # Extract the encrypted content from the gift wrap
            encrypted_content = gift_wrap_event.content()
            
            # Get the sender's public key from the gift wrap event
            sender_pubkey = gift_wrap_event.author()
            
            # Decrypt using NIP-44
            # This creates a shared secret between us and the sender
            decrypted = nip44_decrypt(
                self.keys.secret_key(),  # Our private key
                sender_pubkey,            # Sender's public key
                encrypted_content         # The encrypted payload
            )
            
            print(f"✅ Successfully decrypted gift wrap from {sender_pubkey.to_bech32()[:16]}...")
            return decrypted
            
        except Exception as e:
            print(f"❌ Failed to decrypt gift wrap: {e}")
            return None
    
    def extract_job_from_decrypted_content(self, decrypted_json: str) -> Optional[Event]:
        """
        Extract the job event from the decrypted content.
        
        The decrypted content should be a rumor (kind 1060) whose content
        field contains the actual job event (kind 25000) as a JSON string.
        
        Structure:
        - Gift Wrap (1059) contains encrypted rumor
        - Rumor (1060) contains job event as JSON in its content field
        - Job Event (25000) is the actual request
        """
        try:
            # Parse the decrypted JSON to get the rumor event
            rumor_data = json.loads(decrypted_json)
            
            # The rumor should be kind 1060
            if rumor_data.get('kind') != 1060:
                print(f"⚠️ Expected rumor (kind 1060), got kind {rumor_data.get('kind')}")
                return None
            
            # The rumor's content contains the actual job event as JSON
            job_event_json = rumor_data.get('content', '')
            if not job_event_json:
                print("⚠️ Rumor has no content")
                return None
            
            # Parse the job event JSON manually since it's unsigned
            job_data = json.loads(job_event_json)
            
            # Verify it's a job request (kind 25000)
            if job_data.get('kind') != 25000:
                print(f"⚠️ Expected job request (kind 25000), got kind {job_data.get('kind')}")
                return None
            
            # Create a temporary event-like object that we can work with
            # We don't need a full Event object, just the data
            print(f"📋 Extracted job request data (kind {job_data.get('kind')})")
            return job_data
            
        except json.JSONDecodeError as e:
            print(f"❌ Failed to parse JSON: {e}")
            return None
        except Exception as e:
            print(f"❌ Failed to extract job event: {e}")
            return None
    
    def extract_input_from_event(self, event: Event) -> str:
        """Extract input data from job request event"""
        # Look for 'i' tag (input tag)
        for tag in event.tags().to_vec():
            tag_vec = tag.as_vec()
            if len(tag_vec) >= 2 and tag_vec[0] == "i":
                return tag_vec[1]
        
        # Fallback to event content if no 'i' tag
        return event.content()
    
    async def process_job_request(self, event: Event) -> Optional[str]:
        """Process echo job - just return the input"""
        input_data = self.extract_input_from_event(event)
        if not input_data:
            return None
        
        print(f"🔊 Echoing: {input_data}")
        
        # Just echo back the input
        return f"Echo: {input_data}"
    
    async def send_encrypted_result(self, 
                                   original_event: Event, 
                                   result: str, 
                                   recipient_pubkey: PublicKey,
                                   success: bool = True) -> Optional[Event]:
        """
        Send an encrypted job result using NIP-44 gift wrap.
        
        This follows the same encryption pattern as the request:
        1. Create the result event (kind 25000)
        2. Wrap it in a rumor (kind 1060)
        3. Encrypt the rumor using NIP-44
        4. Wrap the encrypted data in a gift wrap (kind 1059)
        5. Send the gift wrap to the relay
        """
        
        try:
            # Step 1: Create the result event (kind 25000)
            # This is the actual response that the client will eventually see
            result_tags = [
                Tag.parse(["e", original_event.id().to_hex()]),  # Reference original request
                Tag.parse(["p", original_event.author().to_hex()]),  # Tag the requester
            ]
            
            if success:
                result_tags.append(Tag.parse(["status", "success"]))
            else:
                result_tags.append(Tag.parse(["status", "error"]))
            
            result_event_builder = EventBuilder(kind=Kind(25000), content=result)
            result_event_builder = result_event_builder.tags(result_tags)
            result_event = result_event_builder.build(self.keys.public_key())
            
            # Step 2: Create a rumor (kind 1060) containing the result event
            # The rumor is an unsigned wrapper that preserves anonymity
            rumor = {
                "kind": 1060,
                "content": result_event.as_json(),  # The result event as JSON
                "created_at": Timestamp.now().as_secs(),
                "tags": []  # Rumors typically don't have tags
            }
            rumor_json = json.dumps(rumor)
            
            # Step 3: Encrypt the rumor using NIP-44
            # This creates end-to-end encryption between us and the recipient
            encrypted_payload = nip44_encrypt(
                self.keys.secret_key(),  # Our private key
                recipient_pubkey,        # Recipient's public key
                rumor_json,             # The rumor as JSON string
                Nip44Version.V2        # Use version 2 of NIP-44
            )
            
            # Step 4: Create the gift wrap (kind 1059)
            # The gift wrap is the outer envelope that only shows the recipient
            gift_wrap_builder = EventBuilder(
                kind=Kind(1059),
                content=encrypted_payload  # The encrypted rumor
            )
            
            # Add p-tag to indicate the recipient (this is public)
            # This is the ONLY information visible to relays and other users
            gift_wrap_builder = gift_wrap_builder.tags([Tag.parse(["p", recipient_pubkey.to_hex()])])
            
            # Step 5: Send the gift wrap
            await self.client.send_event_builder(gift_wrap_builder)
            gift_wrap_event = gift_wrap_builder.build(self.keys.public_key())
            
            status_msg = "success ✅" if success else "error ❌"
            print(f"🔐 Sent encrypted {status_msg} result for job {original_event.id().to_hex()[:8]}")
            print(f"   Gift wrap ID: {gift_wrap_event.id().to_hex()[:8]}...")
            print(f"   Encrypted for: {recipient_pubkey.to_bech32()[:16]}...")
            
            return gift_wrap_event
            
        except Exception as e:
            print(f"❌ Failed to send encrypted result: {e}")
            return None
    
    async def handle_encrypted_request(self, gift_wrap_event: Event):
        """
        Handle an encrypted job request received as a gift wrap.
        
        This is the main processing pipeline for encrypted requests:
        1. Decrypt the gift wrap
        2. Extract the job from the decrypted content
        3. Process the job
        4. Send back an encrypted response
        """
        
        print(f"\n=== 🔐 Processing Encrypted Request ===")
        print(f"Gift wrap ID: {gift_wrap_event.id().to_hex()[:8]}...")
        
        # Step 1: Decrypt the gift wrap
        decrypted_content = self.decrypt_gift_wrap(gift_wrap_event)
        if not decrypted_content:
            print("Failed to decrypt gift wrap - skipping")
            return
        
        # Step 2: Extract the job event from the decrypted content
        job_event = self.extract_job_from_decrypted_content(decrypted_content)
        if not job_event:
            print("Failed to extract job event - skipping")
            return
        
        job_id = job_event.id().to_hex()
        
        # Skip if already processed
        if job_id in self.processed_jobs:
            print(f"Already processed job {job_id[:8]} - skipping")
            return
        
        self.processed_jobs.add(job_id)
        
        # Get the original requester's public key from the job event
        requester_pubkey = job_event.author()
        
        print(f"Job ID: {job_id[:8]}")
        print(f"Requester: {requester_pubkey.to_bech32()[:16]}...")
        print(f"Content: {job_event.content()}")
        
        try:
            # Step 3: Process the job
            result = await self.process_job_request(job_event)
            
            if result is not None:
                # Step 4: Send encrypted successful result
                await self.send_encrypted_result(
                    job_event, 
                    result, 
                    requester_pubkey,
                    success=True
                )
                print(f"✅ Successfully processed encrypted job")
            else:
                # Send encrypted error result
                await self.send_encrypted_result(
                    job_event,
                    "Processing failed",
                    requester_pubkey,
                    success=False
                )
                print("❌ Job processing failed")
                
        except Exception as e:
            print(f"❌ Error processing job {job_id[:8]}: {e}")
            # Try to send encrypted error result
            await self.send_encrypted_result(
                job_event,
                f"Error: {str(e)}",
                requester_pubkey,
                success=False
            )
        
        print("=== Encrypted Job Completed ===\n")
    
    async def send_heartbeat(self):
        """
        Send periodic heartbeat to indicate DVM is online.
        
        Heartbeats remain unencrypted (kind 11998) so that clients can
        discover available DVMs without needing to encrypt messages first.
        """
        while True:
            try:
                # Create heartbeat event (kind 11998) - this remains public
                event_builder = EventBuilder(
                    kind=Kind(11998), 
                    content="online"
                )
                # Add a tag to indicate this DVM supports encryption
                event_builder = event_builder.tags([Tag.parse(["encrypted", "true"])])
                
                await self.client.send_event_builder(event_builder)
                current_time = Timestamp.now()
                print(f"💓 Sent heartbeat at {current_time.as_secs()} (encrypted DVM)")
            except Exception as e:
                print(f"❌ Error sending heartbeat: {e}")
            
            # Wait 30 seconds before next heartbeat
            await asyncio.sleep(30)
    
    async def run(self):
        """Main run loop for the encrypted DVM"""
        if not self.client:
            await self.initialize()
        
        print(f"\n🔐 {self.dvm_name} is now running...")
        print("Listening for encrypted job requests (NIP-44 gift wrap)")
        print("Press Ctrl+C to stop\n")
        
        # Create notification handler for encrypted messages
        class NotificationHandler(HandleNotification):
            def __init__(self, dvm_instance):
                self.dvm_instance = dvm_instance

            async def handle(self, relay_url: str, subscription_id: str, event: Event):
                # Only process gift wrap events (kind 1059) that are for us
                if event.kind().as_u16() == 1059:
                    print(f"🔍 DEBUG: Received gift wrap {event.id().to_hex()[:8]} from {event.author().to_bech32()[:16]}...")
                    
                    # Check if this gift wrap is for us (has our pubkey in p-tag)
                    our_pubkey = self.dvm_instance.keys.public_key().to_hex()
                    for tag in event.tags().to_vec():
                        tag_vec = tag.as_vec()
                        if (len(tag_vec) >= 2 and 
                            tag_vec[0] == "p" and 
                            tag_vec[1] == our_pubkey):
                            print(f"🎁 Gift wrap is for us! Processing...")
                            await self.dvm_instance.handle_encrypted_request(event)
                            return
                    
                    print(f"   Gift wrap not for us (p-tags: {[tag.as_vec() for tag in event.tags().to_vec() if tag.as_vec()[0] == 'p']})")

            async def handle_msg(self, relay_url: str, msg: RelayMessage):
                # Handle relay messages if needed
                pass
        
        handler = NotificationHandler(self)
        
        # Start heartbeat task
        heartbeat_task = asyncio.create_task(self.send_heartbeat())
        
        try:
            # Start handling notifications
            await self.client.handle_notifications(handler)
        finally:
            # Cancel heartbeat task when shutting down
            heartbeat_task.cancel()
            try:
                await heartbeat_task
            except asyncio.CancelledError:
                pass

def load_or_create_keys():
    """Load DVM keys from .env file or create new ones"""
    from pathlib import Path
    
    # Use local .env in the encrypted example directory
    env_file = Path(__file__).parent / ".env"
    
    # Try to load existing keys from .env file first
    if env_file.exists():
        with open(env_file, 'r') as f:
            for line in f:
                if line.strip().startswith("DVM_SECRET_KEY="):
                    nsec = line.strip().split("=", 1)[1].strip('"\'')
                    try:
                        keys = Keys.parse(nsec)
                        print(f"🔑 Loaded existing DVM keys from .env file")
                        return keys
                    except Exception as e:
                        print(f"❌ Error parsing keys from .env: {e}")
                        break
    
    # Generate new keys if none found or parsing failed
    keys = Keys.generate()
    nsec = keys.secret_key().to_bech32()
    npub = keys.public_key().to_bech32()
    pubkey_hex = keys.public_key().to_hex()
    
    # Save to .env file
    env_content = f"""# Encrypted DVM Keys - Auto-generated
# These keys are used for the encrypted Echo DVM example
DVM_SECRET_KEY={nsec}
DVM_NPUB={npub}
DVM_PUBKEY_HEX={pubkey_hex}

# This DVM only accepts encrypted requests using NIP-44 gift wrap
# Clients must encrypt their requests for this specific DVM pubkey
"""
    
    with open(env_file, 'w') as f:
        f.write(env_content)
    
    print(f"🔑 Generated new DVM keys and saved to .env file")
    print(f"DVM NPUB: {npub}")
    print(f"Share this NPUB with clients so they can send encrypted requests")
    
    return keys

async def main():
    """Main function to run the Encrypted Echo DVM"""
    
    print("=" * 60)
    print("🔐 ENCRYPTED ECHO DVM - NIP-44 Gift Wrap Example")
    print("=" * 60)
    print()
    print("This DVM demonstrates end-to-end encryption using NIP-44.")
    print("All job requests and responses are encrypted, ensuring")
    print("privacy from relays and other users.")
    print()
    
    # Load or create DVM keys
    keys = load_or_create_keys()
    
    # Define relay URLs
    relay_urls = [
        "wss://relay.damus.io",
        "wss://nos.lol",
        "wss://relay.primal.net"
    ]
    
    # Create and run the Encrypted Echo DVM
    dvm = EncryptedEchoDVM(keys, relay_urls)
    
    try:
        await dvm.run()
    except KeyboardInterrupt:
        print("\n🔐 Shutting down Encrypted Echo DVM...")

if __name__ == "__main__":
    asyncio.run(main())
