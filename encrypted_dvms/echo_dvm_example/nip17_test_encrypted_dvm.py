import asyncio
import os
import sys
import json
import random
from typing import Optional, Dict
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
    PublicKey,
    nip44_encrypt,
    nip44_decrypt,
    Nip44Version,
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
        encrypted_filter = (
            Filter()
            .kind(Kind(1059))  # Gift wrap events
            .reference(
                f"p:{self.keys.public_key().to_hex()}"
            )  # Filter for p-tag with our pubkey
            .since(Timestamp.now())
        )

        subscription_id = await self.client.subscribe(encrypted_filter)
        print(f"🔐 Subscribed to encrypted responses (kind 1059): {subscription_id}")

    async def create_encrypted_job_request(
        self, input_text: str
    ) -> tuple[Event, Event]:
        """
        Create an encrypted job request using NIP-44 gift wrap.

        This demonstrates the full encryption pipeline:
        1. Create the actual job request (kind 25000), which will remain unsigned
        2. Encrypted the actual job request with sender's private key to DVMs public key
        3. Create the seal event with step 2 data in the content field
        4. Encrypt the seal with a random private key to the DVM's public key
        5. Gift wrap the encrypted seal from step 4 with a random private key

        Returns: gift wrap event
        """

        print(f"\n📝 Creating encrypted job request for: '{input_text}'")

        # 1. Create the actual job request that is unsigned
        print("🔧 Step 1: Creating unsigned job request (kind 25000)...")
        job_request_tags = [
            Tag.parse(["i", input_text, "text/plain"]),  # Input data
            Tag.parse(["category", "echo"]),  # Service category (for DVM's reference)
        ]

        job_request_event_builder = EventBuilder(
            kind=Kind(25000), content=f"Encrypted job request: {input_text}"
        )
        job_request_event_builder = job_request_event_builder.tags(job_request_tags)
        rumor = job_request_event_builder.build(self.keys.public_key()) # build but not sign
        print(f"✅ Created unsigned job request with tags: {[str(tag) for tag in job_request_tags]}")

        # 2. encrypt the actual job request with sender's private key to DVM's public key
        print("🔐 Step 2: Encrypting job request with sender's private key...")
        # Convert the unsigned event to JSON string for encryption
        rumor_json = rumor.as_json()
        encrypted_rumor = nip44_encrypt(self.keys.secret_key(), self.dvm_pubkey, rumor_json, Nip44Version.V2)
        print(f"✅ Encrypted job request (length: {len(encrypted_rumor)} chars)")

        # 3. create the seal event with step 2 data in the content field
        print("🕐 Step 3: Creating seal event (kind 13) with random timestamp...")
        # create a random time up to 2 days in the past
        random_seconds = random.randint(0, 2 * 24 * 60 * 60)
        current_time = Timestamp.now().as_secs()
        random_time_last_2_days = Timestamp.from_secs(current_time - random_seconds)
        seal_event_builder = EventBuilder(kind=Kind(13), content=encrypted_rumor)
        seal_event_builder = seal_event_builder.custom_created_at(random_time_last_2_days)
        signer = NostrSigner.keys(self.keys)
        seal_event = await seal_event_builder.sign(signer)
        print(f"✅ Created and signed seal event with timestamp: {random_time_last_2_days.as_secs()}")

        # 4. encrypt the seal event with a random private key to the DVM's public key
        print("🔑 Step 4: Encrypting seal event with random private key...")
        random_private_key = Keys.generate().secret_key()
        # Convert the seal event to JSON string for encryption
        seal_json = seal_event.as_json()
        encrypted_seal = nip44_encrypt(random_private_key, self.dvm_pubkey, seal_json, Nip44Version.V2)
        print(f"✅ Encrypted seal event (length: {len(encrypted_seal)} chars)")

        # 5. gift wrap the encrypted seal from step 4 with a random private key
        print("🎁 Step 5: Creating gift wrap event (kind 1059)...")
        random_seconds = random.randint(0, 2 * 24 * 60 * 60)
        current_time = Timestamp.now().as_secs()
        random_time_last_2_days = Timestamp.from_secs(current_time - random_seconds)
        random_keys = Keys.generate()
        random_private_key = random_keys.secret_key()
        gift_wrap_builder = EventBuilder(kind=Kind(1059), content=encrypted_seal)
        gift_wrap_builder = gift_wrap_builder.custom_created_at(random_time_last_2_days)
        gift_wrap_builder = gift_wrap_builder.tags([Tag.parse(["p", self.dvm_pubkey.to_hex()])])  # add DVM's relays in that tag too if available
        gift_wrap_signer = NostrSigner.keys(random_keys)
        gift_wrap_event = await gift_wrap_builder.sign(gift_wrap_signer)
        print(f"✅ Created and signed gift wrap event with timestamp: {random_time_last_2_days.as_secs()}")
        print(f"🎯 Final gift wrap event ID: {str(gift_wrap_event.id)[:16]}...")

        return gift_wrap_event

    async def test_encryption_pipeline(self, input_text: str):
        """Test the encryption pipeline without sending to relays"""
        print("\n" + "="*60)
        print("🧪 TESTING ENCRYPTION PIPELINE")
        print("="*60)
        
        try:
            # Test the encryption pipeline
            gift_wrap_event = await self.create_encrypted_job_request(input_text)
            
            print("\n🎉 ENCRYPTION PIPELINE COMPLETED SUCCESSFULLY!")
            print(f"📦 Final gift wrap event created:")
            print(f"   - Event ID: {gift_wrap_event.id}")
            print(f"   - Kind: {gift_wrap_event.kind}")
            print(f"   - Content length: {len(gift_wrap_event.content())} chars")
            print(f"   - Tags: {gift_wrap_event.tags()}")
            
            return gift_wrap_event
            
        except Exception as e:
            print(f"\n❌ Error in encryption pipeline: {e}")
            import traceback
            traceback.print_exc()
            return None


def load_dvm_pubkey():
    """
    Load DVM public key from environment variables or .env file
    """
    from pathlib import Path
    
    # First try environment variables
    dvm_npub = os.getenv("DVM_NPUB")
    if dvm_npub:
        print("🔑 Loaded DVM_NPUB from environment variable")
        return dvm_npub
    
    # Then try .env file in the encrypted example directory
    env_file = Path(__file__).parent / ".env"
    if env_file.exists():
        with open(env_file, 'r') as f:
            for line in f:
                if line.strip().startswith("DVM_NPUB="):
                    npub = line.strip().split("=", 1)[1].strip('"\'')
                    print("🔑 Loaded DVM_NPUB from .env file")
                    return npub
    
    print("❌ DVM_NPUB not found in environment or .env file")
    print("Please set DVM_NPUB environment variable or create .env file with:")
    print("DVM_NPUB=npub1your_dvm_public_key_here")
    return None


async def main():
    """Test the NIP-17 encryption pipeline"""
    print("🔐 NIP-17 Encryption Pipeline Test")
    print("="*50)
    
    # Generate test keys
    client_keys = Keys.generate()
    print(f"🔑 Generated test client keys")
    print(f"   Client npub: {client_keys.public_key().to_bech32()}")
    
    # Load DVM public key from environment or .env file
    dvm_npub = load_dvm_pubkey()
    if not dvm_npub:
        print("\n❌ Cannot proceed without DVM public key")
        print("Please set DVM_NPUB environment variable or create .env file")
        return
    
    print(f"🎯 Target DVM: {dvm_npub[:16]}...")
    
    # Create test client (no relays needed for encryption testing)
    client = EncryptedDVMTestClient(client_keys, [], dvm_npub)
    
    # Test the encryption pipeline
    test_message = "Hello, this is a test of the NIP-17 encryption pipeline!"
    await client.test_encryption_pipeline(test_message)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")