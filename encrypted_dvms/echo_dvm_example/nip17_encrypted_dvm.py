#!/usr/bin/env python3
"""
NIP-17 Encrypted Echo DVM - Demo Version with Detailed Logging
Returns whatever input it receives, using NIP-17 gift wrap encryption with comprehensive demo logging
"""

import asyncio
import os
import json
import random
import time
from datetime import datetime
from typing import Dict, List, Optional
import traceback
from nostr_sdk import (
    Client,
    Keys,
    EventBuilder,
    Filter,
    Kind,
    Tag,
    Timestamp,
    Event,
    HandleNotification,
    RelayMessage,
    NostrSigner,
    RelayUrl,
    nip44_encrypt,
    nip44_decrypt,
    Nip44Version,
    PublicKey,
    UnwrappedGift,
    UnsignedEvent,
)


class DemoLogger:
    """Helper class for beautiful demo logging"""
    
    @staticmethod
    def print_header(title: str):
        print("\n" + "="*80)
        print(f"🎭 {title}")
        print("="*80)
    
    @staticmethod
    def print_step(step_num: int, title: str, details: str = ""):
        print(f"\n📋 Step {step_num}: {title}")
        if details:
            print(f"   {details}")
    
    @staticmethod
    def print_timing(label: str):
        current_time = datetime.now()
        timestamp = current_time.strftime("%H:%M:%S.%f")[:-3]  # Include milliseconds
        print(f"⏰ {label}: {timestamp}")
    
    @staticmethod
    def print_npub(label: str, pubkey: PublicKey, show_full: bool = False):
        npub = pubkey.to_bech32()
        if show_full:
            print(f"🔑 {label}: {npub}")
        else:
            print(f"🔑 {label}: {npub[:16]}...{npub[-8:]}")
    
    @staticmethod
    def print_random_npub(label: str):
        """Print a random npub to show anonymity features"""
        random_keys = Keys.generate()
        random_npub = random_keys.public_key().to_bech32()
        print(f"🎲 {label} (random): {random_npub[:16]}...{random_npub[-8:]}")
    
    @staticmethod
    def print_encryption_info(encrypted_data: str):
        print(f"🔐 Encrypted payload length: {len(encrypted_data)} characters")
        print(f"🔐 Encrypted preview: {encrypted_data[:40]}...")
    
    @staticmethod
    def print_success(message: str):
        print(f"✅ {message}")
    
    @staticmethod
    def print_error(message: str):
        print(f"❌ {message}")


class NIP17EncryptedEchoDVM:
    """
    NIP-17 Encrypted Echo DVM with comprehensive demo logging.
    
    This DVM demonstrates:
    - Receiving NIP-17 gift wrap encrypted requests
    - Decrypting them step-by-step with detailed logging
    - Processing echo jobs (same as regular DVM)
    - Encrypting responses using NIP-17 gift wrap
    - Tracking user npubs while showing anonymity features
    """

    def __init__(
        self, keys: Keys, relay_urls: List[str], dvm_name: str = "NIP-17 Encrypted Echo DVM"
    ):
        self.keys = keys
        self.relay_urls = relay_urls
        self.dvm_name = dvm_name
        self.client = None
        self.logger = DemoLogger()

        # Track processed jobs to avoid duplicates
        self.processed_jobs = set()
        
        # Demo: Track user interactions (real DVMs would use this for analytics)
        self.user_interactions = {}

        self.logger.print_header(f"Initializing {dvm_name}")
        print(f"🏗️  Setting up encrypted DVM with NIP-17 gift wrap support")
        self.logger.print_npub("DVM Public Key", self.keys.public_key(), show_full=True)
        print("🔐 This DVM ONLY accepts encrypted requests via NIP-17 gift wrap")
        print("📊 Demo: Tracking user interactions for analytics demonstration")

    async def initialize(self):
        """Initialize the Nostr client and connect to relays"""
        self.logger.print_header("Connecting to Nostr Network")
        
        signer = NostrSigner.keys(self.keys)
        self.client = Client(signer)

        # Add relays with demo logging
        print("🌐 Adding relays...")
        for i, relay_url in enumerate(self.relay_urls, 1):
            relay = RelayUrl.parse(relay_url)
            await self.client.add_relay(relay)
            print(f"   {i}. {relay_url} ✅")

        # Connect to relays
        print("\n🔗 Connecting to relays...")
        self.logger.print_timing("Connection started")
        await self.client.connect()
        self.logger.print_timing("Connection completed")
        self.logger.print_success("Connected to all relays")

        # Subscribe to encrypted job requests
        await self.subscribe_to_encrypted_requests()

    async def subscribe_to_encrypted_requests(self):
        """Subscribe to encrypted gift wrap events (kind 1059) with demo logging"""
        
        self.logger.print_header("Setting Up Encrypted Subscriptions")
        
        print("🎯 Subscribing to NIP-17 gift wrap events (kind 1059)")
        print("📝 Note: We subscribe to ALL gift wraps, then filter for ours in the handler")
        print("🔍 This is because gift wrap p-tags might not filter reliably on all relays")
        
        # Filter for ALL gift wraps (kind 1059) - we'll filter by p-tag in the handler
        # Subscribe to events from 2 days ago to catch gift wraps with random timestamps
        two_days_ago = Timestamp.now().as_secs() - (2 * 24 * 60 * 60)
        encrypted_filter = (
            Filter().kind(Kind(1059)).since(Timestamp.from_secs(two_days_ago))  # Gift wrap events
        )
        
        print(f"🕐 Subscribing to gift wraps from 2 days ago onwards (timestamp: {two_days_ago})")
        print(f"   This matches the random timestamp range used by clients")

        subscription = await self.client.subscribe(encrypted_filter)
        self.logger.print_success(f"Subscribed to gift wraps: {subscription}")
        
        # Show some demo info about what we're listening for
        our_pubkey_hex = self.keys.public_key().to_hex()
        our_npub = self.keys.public_key().to_bech32()
        print(f"🔑 DVM will only process gift wraps with p-tag: {our_pubkey_hex}")
        print(f"🔑 DVM npub (for client reference): {our_npub}")
        print("⏳ Waiting for encrypted job requests...")
        print("📝 Note: Other users' gift wraps will be silently ignored to reduce log noise")

    async def decrypt_gift_wrap(self, gift_wrap_event: Event) -> Optional[Event]:
        """
        Decrypt a NIP-17 gift wrap event - REVERSE of encryption process with detailed demo logging.
        
        This mirrors the test client's encryption steps in REVERSE order:
        
        CLIENT ENCRYPTION STEPS:                   
        1. Create the job request (kind 25000), which will remain unsigned
        2. Encrypt the job request with sender's private key to DVM's public key
        3. Create the seal event (kind 13) with step 2 data in the content field
        4. Encrypt the seal with a random private key to the DVM's public key
        5. Gift wrap the encrypted seal from step 4 with a random private key   
        
        DVM DECRYPTION STEPS (this method):
        1. Receive gift wrap (kind 1059)
        2. Decrypt gift wrap content → get seal event JSON
        3. Parse seal event (kind 13) from JSON
        4. Decrypt seal content → get original job request JSON  
        5. Parse job request (kind 25000) from JSON

        Returns the inner job event (kind 25000) or None if decryption fails.
        """
        
        self.logger.print_header("🔓 DECRYPTING GIFT WRAP (Reverse of Client Encryption)")
        
        try:
            # Step 1: Analyze the received gift wrap (kind 1059)
            self.logger.print_step(1, "Analyzing Received Gift Wrap (kind 1059)")
            print(f"   📦 Gift wrap ID: {gift_wrap_event.id().to_hex()[:16]}...")
            print(f"   📅 Created at: {datetime.fromtimestamp(gift_wrap_event.created_at().as_secs())}")
            self.logger.print_npub("   🎭 Apparent sender", gift_wrap_event.author())
            print("   ⚠️  Note: This sender is RANDOM for anonymity (from client step 5)!")
            
            # Pretty print the full gift wrap event
            print("   📄 FULL GIFT WRAP EVENT:")
            gift_wrap_json = json.loads(gift_wrap_event.as_json())
            print(json.dumps(gift_wrap_json, indent=4))
            
            # Show the encrypted content that we need to decrypt
            self.logger.print_encryption_info(gift_wrap_event.content())
            print("   📋 This encrypted content contains the seal event from client step 4")
            
            # Step 2: Decrypt the gift wrap content to get seal event JSON
            self.logger.print_step(2, "Decrypting Gift Wrap → Seal Event JSON")
            print("   🔄 This reverses client Step 4: 'Encrypt seal with random private key'")
            self.logger.print_timing("Gift wrap decryption started")
            
            # Use NIP-44 to decrypt the gift wrap content
            decrypted_seal_json = nip44_decrypt(
                self.keys.secret_key(),      # Our private key (DVM)
                gift_wrap_event.author(),    # Gift wrap sender's public key (random from step 5)
                gift_wrap_event.content(),   # Encrypted seal event
            )
            
            self.logger.print_timing("Gift wrap decryption completed")
            print(f"   ✅ Successfully decrypted seal event JSON (length: {len(decrypted_seal_json)} chars)")
            
            # Pretty print the decrypted seal JSON
            print("   📄 DECRYPTED SEAL EVENT JSON:")
            try:
                seal_json_formatted = json.loads(decrypted_seal_json)
                print(json.dumps(seal_json_formatted, indent=4))
            except json.JSONDecodeError:
                print(f"   📋 Raw seal JSON (not valid JSON): {decrypted_seal_json}")
            print(f"   📋 This contains the seal event from client step 3")
            
            # Step 3: Parse the seal event (kind 13) from JSON
            self.logger.print_step(3, "Parsing Seal Event (kind 13)")
            print("   🔄 This extracts the seal event from client step 3")
            
            seal_event = Event.from_json(decrypted_seal_json)
            
            # Validate it's a seal event
            if seal_event.kind().as_u16() != 13:
                self.logger.print_error(f"Expected seal event (kind 13), got kind {seal_event.kind().as_u16()}")
                return None
                
            print(f"   ✅ Confirmed seal event (kind 13)")
            print(f"   📅 Seal timestamp: {datetime.fromtimestamp(seal_event.created_at().as_secs())}")
            self.logger.print_npub("   🔑 Seal author", seal_event.author())
            
            # Pretty print the full seal event
            print("   📄 FULL SEAL EVENT:")
            seal_json_obj = json.loads(seal_event.as_json())
            print(json.dumps(seal_json_obj, indent=4))
            
            print("   📋 Seal contains encrypted job request from client step 2")
            self.logger.print_encryption_info(seal_event.content())
            
            # Step 4: Decrypt the seal content to get original job request JSON
            self.logger.print_step(4, "Decrypting Seal Content → Job Request JSON")
            print("   🔄 This reverses client Step 2: 'Encrypt job request with sender's key'")
            self.logger.print_timing("Seal decryption started")
            
            # Use NIP-44 to decrypt the seal content
            decrypted_job_json = nip44_decrypt(
                self.keys.secret_key(),      # Our private key (DVM)
                seal_event.author(),         # Seal sender's public key (real client)
                seal_event.content(),        # Encrypted job request
            )
            
            self.logger.print_timing("Seal decryption completed")
            print(f"   ✅ Successfully decrypted job request JSON (length: {len(decrypted_job_json)} chars)")
            
            # Pretty print the decrypted job JSON
            print("   📄 DECRYPTED JOB REQUEST JSON:")
            try:
                job_json_formatted = json.loads(decrypted_job_json)
                print(json.dumps(job_json_formatted, indent=4))
            except json.JSONDecodeError:
                print(f"   📋 Raw job JSON (not valid JSON): {decrypted_job_json}")
            print(f"   📋 This contains the original job request from client step 1")
            
            # Step 5: Parse the job request (kind 25000) from JSON
            self.logger.print_step(5, "Parsing Job Request (kind 25000)")
            print("   🔄 This extracts the original job request from client step 1")
            
            # Parse the job event (could be signed or unsigned)
            try:
                job_event = Event.from_json(decrypted_job_json)
                print("   📝 Parsed as signed event")
                real_sender = job_event.author()
            except:
                try:
                    job_event = UnsignedEvent.from_json(decrypted_job_json)
                    print("   📝 Parsed as unsigned event")
                    # For unsigned events, the real sender is the seal author
                    real_sender = seal_event.author()
                except Exception as parse_error:
                    self.logger.print_error(f"Failed to parse job event: {parse_error}")
                    return None
            
            # Validate it's a job request
            if job_event.kind().as_u16() != 25000:
                self.logger.print_error(f"Expected job request (kind 25000), got kind {job_event.kind().as_u16()}")
                return None
            
            # Demo: Track user interaction
            self.logger.print_npub("🎯 REAL sender discovered", real_sender, show_full=True)
            print("   ✨ This is the actual user who created the original job request!")
            
            sender_npub = real_sender.to_bech32()
            if sender_npub not in self.user_interactions:
                self.user_interactions[sender_npub] = {
                    'first_seen': datetime.now(),
                    'request_count': 0,
                    'last_request': None
                }
            
            self.user_interactions[sender_npub]['request_count'] += 1
            self.user_interactions[sender_npub]['last_request'] = datetime.now()
            
            print(f"📊 Demo Analytics: User {sender_npub[:16]}... has made {self.user_interactions[sender_npub]['request_count']} request(s)")
            
            # Pretty print the final job event
            print("   📄 FINAL JOB REQUEST EVENT:")
            if hasattr(job_event, 'as_json'):
                final_job_json = json.loads(job_event.as_json())
                print(json.dumps(final_job_json, indent=4))
            else:
                # For unsigned events, show what we can
                print(f"   📋 Unsigned job event - Kind: {job_event.kind().as_u16()}")
                print(f"   📋 Content: {job_event.content()}")
                print(f"   📋 Tags: {[tag.as_vec() for tag in job_event.tags().to_vec()]}")
            
            # Final validation and demo output
            self.logger.print_success("🎉 DECRYPTION COMPLETE - Successfully reversed all client encryption steps!")
            print(f"   📋 Final job content: {job_event.content()}")
            
            # Show job tags for demo
            print("   🏷️  Job tags (from original client step 1):")
            for tag in job_event.tags().to_vec():
                tag_vec = tag.as_vec()
                if len(tag_vec) >= 2:
                    print(f"      - {tag_vec[0]}: {tag_vec[1]}")
            
            print("\n🔄 DECRYPTION SUMMARY:")
            print("   1. ✅ Received gift wrap (kind 1059) with random sender")
            print("   2. ✅ Decrypted gift wrap → seal event JSON")
            print("   3. ✅ Parsed seal event (kind 13)")
            print("   4. ✅ Decrypted seal content → job request JSON") 
            print("   5. ✅ Parsed original job request (kind 25000)")
            print("   🎯 Ready to process the decrypted job request!")
            
            return job_event

        except Exception as e:
            self.logger.print_error(f"Failed to decrypt gift wrap: {e}")
            print(f"🔍 Debug info: {traceback.format_exc()}")
            print("\n❌ DECRYPTION FAILED - Could not reverse client encryption steps")
            return None

    def extract_input_from_event(self, event) -> str:
        """Extract input data from job request event (works with Event or UnsignedEvent)"""
        # Look for 'i' tag (input tag)
        for tag in event.tags().to_vec():
            tag_vec = tag.as_vec()
            if len(tag_vec) >= 2 and tag_vec[0] == "i":
                return tag_vec[1]

        # Fallback to event content if no 'i' tag
        return event.content()

    async def process_job_request(self, event: Event) -> Optional[str]:
        """Process echo job with demo logging"""
        
        self.logger.print_header("🔊 PROCESSING ECHO JOB")
        
        # Extract input with demo logging
        self.logger.print_step(1, "Extracting Input Data")
        input_data = self.extract_input_from_event(event)
        
        if not input_data:
            self.logger.print_error("No input data found in job request")
            return None

        print(f"   📝 Input received: '{input_data}'")
        print(f"   📏 Input length: {len(input_data)} characters")
        
        # Demo: Show processing time
        self.logger.print_step(2, "Processing Echo Job")
        self.logger.print_timing("Processing started")
        
        # Simulate some processing time for demo
        await asyncio.sleep(0.1)
        
        # Create echo response
        echo_response = f"Echo: {input_data}"
        
        self.logger.print_timing("Processing completed")
        self.logger.print_success(f"Echo response: '{echo_response}'")
        
        return echo_response

    async def send_encrypted_result(
        self,
        original_event: Event,
        result: str,
        recipient_pubkey: PublicKey,
        success: bool = True,
    ) -> Optional[Event]:
        """
        Send an encrypted job result using NIP-17 gift wrap with detailed demo logging.
        """
        
        self.logger.print_header("🔐 ENCRYPTING RESPONSE")
        
        try:
            # Step 1: Create the result event
            self.logger.print_step(1, "Creating Result Event (kind 25000)")
            
            result_tags = [
                Tag.parse(["e", original_event.id().to_hex()]),  # Reference original request
                Tag.parse(["p", original_event.author().to_hex()]),  # Tag the requester
            ]

            if success:
                result_tags.append(Tag.parse(["status", "success"]))
                print("   ✅ Status: success")
            else:
                result_tags.append(Tag.parse(["status", "error"]))
                print("   ❌ Status: error")

            result_event_builder = EventBuilder(kind=Kind(25000), content=result)
            result_event_builder = result_event_builder.tags(result_tags)
            result_event = result_event_builder.build(self.keys.public_key())
            
            print(f"   📋 Result content: '{result}'")
            print(f"   🏷️  Result tags: {len(result_tags)} tags added")

            # Step 2: Create rumor wrapper
            self.logger.print_step(2, "Creating Rumor Wrapper (kind 1060)")
            
            # Create random timestamp for anonymity
            random_seconds = random.randint(0, 2 * 24 * 60 * 60)  # Up to 2 days ago
            current_time = Timestamp.now().as_secs()
            random_timestamp = current_time - random_seconds
            
            rumor = {
                "kind": 1060,
                "content": result_event.as_json(),
                "created_at": random_timestamp,
                "tags": [],
            }
            rumor_json = json.dumps(rumor)
            
            print(f"   📅 Random timestamp: {datetime.fromtimestamp(random_timestamp)}")
            print(f"   📦 Rumor JSON length: {len(rumor_json)} characters")

            # Step 3: Encrypt the rumor
            self.logger.print_step(3, "Encrypting Rumor with NIP-44")
            self.logger.print_timing("Encryption started")
            
            encrypted_payload = nip44_encrypt(
                self.keys.secret_key(),  # Our private key
                recipient_pubkey,        # Recipient's public key
                rumor_json,             # The rumor as JSON string
                Nip44Version.V2,        # Use version 2 of NIP-44
            )
            
            self.logger.print_timing("Encryption completed")
            self.logger.print_encryption_info(encrypted_payload)
            self.logger.print_npub("🎯 Encrypted for", recipient_pubkey)

            # Step 4: Create gift wrap with random sender
            self.logger.print_step(4, "Creating Gift Wrap (kind 1059)")
            
            # Generate random keys for anonymity
            random_keys = Keys.generate()
            self.logger.print_npub("🎭 Random gift wrap sender", random_keys.public_key())
            print("   ⚠️  This random sender provides anonymity!")
            
            # Create random timestamp for gift wrap
            random_seconds = random.randint(0, 2 * 24 * 60 * 60)
            random_timestamp = current_time - random_seconds
            
            gift_wrap_builder = EventBuilder(kind=Kind(1059), content=encrypted_payload)
            gift_wrap_builder = gift_wrap_builder.custom_created_at(Timestamp.from_secs(random_timestamp))
            gift_wrap_builder = gift_wrap_builder.tags([
                Tag.parse(["p", recipient_pubkey.to_hex()])
            ])
            
            print(f"   📅 Gift wrap timestamp: {datetime.fromtimestamp(random_timestamp)}")

            # Step 5: Send the gift wrap
            self.logger.print_step(5, "Sending Encrypted Response")
            self.logger.print_timing("Send started")
            
            await self.client.send_event_builder(gift_wrap_builder)
            
            # Build the event for logging (using random keys)
            random_signer = NostrSigner.keys(random_keys)
            gift_wrap_event = await gift_wrap_builder.sign(random_signer)
            
            self.logger.print_timing("Send completed")
            
            status_msg = "SUCCESS" if success else "ERROR"
            self.logger.print_success(f"Sent encrypted {status_msg} response!")
            print(f"   📦 Gift wrap ID: {gift_wrap_event.id().to_hex()[:16]}...")
            
            # Demo: Show delivery info
            print(f"\n📊 Demo Delivery Summary:")
            print(f"   🎯 Delivered to: {recipient_pubkey.to_bech32()[:16]}...{recipient_pubkey.to_bech32()[-8:]}")
            print(f"   🔐 Encryption: NIP-44 v2 end-to-end")
            print(f"   🎭 Anonymity: Random sender and timestamps")
            print(f"   📏 Total encrypted size: {len(encrypted_payload)} chars")

            return gift_wrap_event

        except Exception as e:
            self.logger.print_error(f"Failed to send encrypted result: {e}")
            print(f"🔍 Debug: {traceback.format_exc()}")
            return None

    async def handle_encrypted_request(self, gift_wrap_event: Event):
        """
        Handle an encrypted job request with comprehensive demo logging.
        
        This orchestrates the complete flow:
        1. Decrypt the gift wrap
        2. Process the echo job  
        3. Send encrypted response
        """

        self.logger.print_header("🎭 NEW ENCRYPTED REQUEST RECEIVED")
        self.logger.print_timing("Request processing started")
        
        print(f"📦 Gift wrap event ID: {gift_wrap_event.id().to_hex()[:16]}...")
        self.logger.print_npub("🎭 Gift wrap sender", gift_wrap_event.author())
        print("⚠️  Note: This sender is RANDOM - the real sender is encrypted inside!")

        # Step 1: Decrypt the gift wrap
        job_event = await self.decrypt_gift_wrap(gift_wrap_event)
        if not job_event:
            self.logger.print_error("Failed to decrypt gift wrap - skipping request")
            return

        # Get job details
        job_id = job_event.id().to_hex() if hasattr(job_event, 'id') else "unsigned"
        
        # Skip if already processed
        if job_id in self.processed_jobs:
            print(f"⏭️  Already processed job {job_id[:8]} - skipping")
            return

        self.processed_jobs.add(job_id)

        # Get the real requester's public key
        if hasattr(job_event, 'author'):
            requester_pubkey = job_event.author()
        else:
            # For unsigned events, we need to get the author from the unwrapped gift
            # This is a bit tricky - let's extract it from the gift wrap decryption
            signer = NostrSigner.keys(self.keys)
            unwrapped_gift = await UnwrappedGift.from_gift_wrap(signer, gift_wrap_event)
            requester_pubkey = unwrapped_gift.sender()

        self.logger.print_header("📋 JOB REQUEST DETAILS")
        print(f"🆔 Job ID: {job_id[:16] if job_id != 'unsigned' else 'unsigned'}...")
        self.logger.print_npub("👤 Real requester", requester_pubkey, show_full=True)
        print(f"📝 Job content: {job_event.content()}")

        try:
            # Step 2: Process the job
            result = await self.process_job_request(job_event)

            if result is not None:
                # Step 3: Send encrypted successful result
                await self.send_encrypted_result(
                    job_event, result, requester_pubkey, success=True
                )
                
                self.logger.print_header("🎉 REQUEST COMPLETED SUCCESSFULLY")
                self.logger.print_timing("Request processing completed")
                print(f"✅ Processed and responded to encrypted job request")
                
            else:
                # Send encrypted error result
                await self.send_encrypted_result(
                    job_event, "Processing failed", requester_pubkey, success=False
                )
                self.logger.print_error("Job processing failed - sent error response")

        except Exception as e:
            self.logger.print_error(f"Error processing job: {e}")
            print(f"🔍 Debug: {traceback.format_exc()}")
            
            # Try to send encrypted error result
            try:
                await self.send_encrypted_result(
                    job_event, f"Error: {str(e)}", requester_pubkey, success=False
                )
            except:
                self.logger.print_error("Failed to send error response")

        # Demo: Show current stats
        print(f"\n📊 Demo Statistics:")
        print(f"   🔢 Total processed jobs: {len(self.processed_jobs)}")
        print(f"   👥 Unique users served: {len(self.user_interactions)}")
        if self.user_interactions:
            most_active_user = max(self.user_interactions.items(), key=lambda x: x[1]['request_count'])
            print(f"   🏆 Most active user: {most_active_user[0][:16]}... ({most_active_user[1]['request_count']} requests)")

    async def send_heartbeat(self):
        """Send periodic heartbeat with demo logging"""
        heartbeat_count = 0
        
        while True:
            try:
                heartbeat_count += 1
                
                # Create heartbeat event (kind 11998) - remains unencrypted for discovery
                event_builder = EventBuilder(kind=Kind(11998), content="online")
                event_builder = event_builder.tags([Tag.parse(["encrypted", "nip17"])])

                await self.client.send_event_builder(event_builder)
                
                current_time = datetime.now()
                print(f"\n💓 Heartbeat #{heartbeat_count} sent at {current_time.strftime('%H:%M:%S')}")
                print(f"   🔐 Advertising: NIP-17 encrypted DVM online")
                print(f"   👥 Users served: {len(self.user_interactions)}")
                
            except Exception as e:
                self.logger.print_error(f"Error sending heartbeat: {e}")

            # Wait 30 seconds before next heartbeat
            await asyncio.sleep(30)

    async def run(self):
        """Main run loop with demo logging"""
        if not self.client:
            await self.initialize()

        self.logger.print_header(f"🚀 {self.dvm_name} IS NOW RUNNING")
        print("🔐 Listening for NIP-17 encrypted job requests")
        print("📊 Demo mode: Comprehensive logging enabled")
        print("🎭 Privacy features: Tracking real users while showing anonymity")
        print("\n⌨️  Press Ctrl+C to stop")
        
        # Show some demo info
        print(f"\n🔑 DVM Identity:")
        self.logger.print_npub("   Public Key", self.keys.public_key(), show_full=True)
        print(f"   🌐 Connected to {len(self.relay_urls)} relays")
        print(f"   📡 Listening on kind 1059 (gift wraps)")

        # Create notification handler
        class NotificationHandler(HandleNotification):
            def __init__(self, dvm_instance):
                self.dvm_instance = dvm_instance

            async def handle(self, relay_url: str, subscription_id: str, event: Event):
                # Only process gift wrap events (kind 1059) that are actually for us
                if event.kind().as_u16() == 1059:
                    # Check if this gift wrap is for us (has our pubkey in p-tag)
                    our_pubkey = self.dvm_instance.keys.public_key().to_hex()
                    
                    for tag in event.tags().to_vec():
                        tag_vec = tag.as_vec()
                        if len(tag_vec) >= 2 and tag_vec[0] == "p" and tag_vec[1] == our_pubkey:
                            # Only log and process if it's for us
                            print(f"\n🎯 RECEIVED GIFT WRAP FOR US!")
                            print(f"   📦 Event ID: {event.id().to_hex()[:8]}... from {relay_url}")
                            print(f"   🎭 Apparent sender: {event.author().to_bech32()[:16]}...")
                            print(f"   📅 Created: {datetime.fromtimestamp(event.created_at().as_secs())}")
                            
                            await self.dvm_instance.handle_encrypted_request(event)
                            break
                    # All other gift wraps are completely ignored (no logging at all)

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
        with open(env_file, "r") as f:
            for line in f:
                if line.strip().startswith("DVM_SECRET_KEY="):
                    nsec = line.strip().split("=", 1)[1].strip("\"'")
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
    env_content = f"""# NIP-17 Encrypted DVM Keys - Auto-generated
# These keys are used for the NIP-17 Encrypted Echo DVM example
DVM_SECRET_KEY={nsec}
DVM_NPUB={npub}
DVM_PUBKEY_HEX={pubkey_hex}

# This DVM only accepts encrypted requests using NIP-17 gift wrap
# Clients must encrypt their requests for this specific DVM pubkey
"""

    with open(env_file, "w") as f:
        f.write(env_content)

    print(f"🔑 Generated new DVM keys and saved to .env file")
    print(f"DVM NPUB: {npub}")
    print(f"Share this NPUB with clients so they can send encrypted requests")

    return keys


async def main():
    """Main function to run the NIP-17 Encrypted Echo DVM"""

    print("=" * 80)
    print("🎭 NIP-17 ENCRYPTED ECHO DVM - DEMO VERSION")
    print("=" * 80)
    print()
    print("This DVM demonstrates NIP-17 gift wrap encryption with comprehensive")
    print("demo logging. Every step of encryption/decryption is shown, along with")
    print("user tracking capabilities while preserving anonymity features.")
    print()
    print("🔐 Features demonstrated:")
    print("   • NIP-17 gift wrap encryption/decryption")
    print("   • Step-by-step processing with timestamps")
    print("   • Real vs anonymous npub tracking")
    print("   • User analytics while preserving privacy")
    print("   • Random timestamps and senders for anonymity")
    print()

    # Load or create DVM keys
    keys = load_or_create_keys()

    # Define relay URLs
    relay_urls = ["wss://relay.damus.io", "wss://nos.lol", "wss://relay.primal.net"]

    # Create and run the NIP-17 Encrypted Echo DVM
    dvm = NIP17EncryptedEchoDVM(keys, relay_urls)

    try:
        await dvm.run()
    except KeyboardInterrupt:
        print("\n🎭 Shutting down NIP-17 Encrypted Echo DVM...")
        print("👋 Demo completed - thanks for watching!")


if __name__ == "__main__":
    asyncio.run(main())
