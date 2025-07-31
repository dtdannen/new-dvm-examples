#!/usr/bin/env python3
"""
Test client for Echo DVM - Sends job requests and waits for responses
"""

import asyncio
import os
import sys
from typing import Optional
from nostr_sdk import (
    Client, Keys, EventBuilder, Filter, Kind, Tag, Timestamp, 
    Event, HandleNotification, RelayMessage, NostrSigner, RelayUrl, PublicKey
)

class DVMTestClient:
    """
    Simple test client to send job requests to DVMs
    """
    
    def __init__(self, keys: Keys, relay_urls: list):
        self.keys = keys
        self.relay_urls = relay_urls
        self.client = None
        self.waiting_for_response = {}
        
        print(f"Test Client Public Key: {self.keys.public_key().to_bech32()}")
    
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
        
        # Subscribe to responses
        await self.subscribe_to_responses()
    
    async def subscribe_to_responses(self):
        """Subscribe to DVM responses directed at us"""
        # Subscribe to kind 25000 events that tag us (responses to our requests)
        filter_responses = (Filter()
                           .kind(Kind(25000))
                           .pubkey(self.keys.public_key())
                           .since(Timestamp.now()))
        
        subscription_id = await self.client.subscribe(filter_responses)
        print(f"Subscribed to responses: {subscription_id}")
    
    def extract_referenced_event(self, event: Event) -> Optional[str]:
        """Extract the event ID that this event is referencing"""
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
    
    async def send_job_request(self, 
                             input_text: str,
                             dvm_pubkey: Optional[str] = None,
                             category: str = "echo") -> Event:
        """Send a job request to a DVM"""
        
        # Create job request tags
        tags = [
            Tag.parse(["i", input_text, "text/plain"]),  # Input data
            Tag.parse(["category", category]),            # Service category
            Tag.parse(["t", category])                    # Hashtag for discovery
        ]
        
        # If specific DVM is targeted, add p-tag
        if dvm_pubkey:
            tags.append(Tag.parse(["p", dvm_pubkey]))
        
        # Create the job request event (kind 25000)
        event_builder = EventBuilder(kind=Kind(25000), content=f"Job request: {input_text}")
        # Add tags using the tags method
        event_builder = event_builder.tags(tags)
        
        # Send the request
        await self.client.send_event_builder(event_builder)
        job_request = event_builder.build(self.keys.public_key())
        
        # Track that we're waiting for a response
        job_id = job_request.id().to_hex()
        self.waiting_for_response[job_id] = {
            "input": input_text,
            "timestamp": asyncio.get_event_loop().time(),
            "completed": False
        }
        
        print(f"Sent job request: {job_id[:8]}")
        print(f"Input: '{input_text}'")
        if dvm_pubkey:
            print(f"Targeted DVM: {dvm_pubkey[:8]}...")
        else:
            print(f"Open request for category: {category}")
        print()
        
        return job_request
    
    async def handle_response(self, event: Event):
        """Handle a response from a DVM"""
        # Check if this is a response to one of our requests
        referenced_event_id = self.extract_referenced_event(event)
        if not referenced_event_id or referenced_event_id not in self.waiting_for_response:
            return
        
        # Get the original request info
        request_info = self.waiting_for_response[referenced_event_id]
        if request_info["completed"]:
            return  # Already handled this response
        
        request_info["completed"] = True
        
        # Extract response details
        status = self.get_status_from_event(event)
        response_content = event.content()
        dvm_pubkey = event.author().to_bech32()
        
        # Calculate response time
        response_time = asyncio.get_event_loop().time() - request_info["timestamp"]
        
        print(f"=== Response Received ===")
        print(f"Request ID: {referenced_event_id[:8]}")
        print(f"Original Input: '{request_info['input']}'")
        print(f"DVM Response: '{response_content}'")
        print(f"Status: {status}")
        print(f"DVM: {dvm_pubkey}")
        print(f"Response Time: {response_time:.2f} seconds")
        print("========================\n")
    
    async def run_interactive_test(self):
        """Run interactive test session"""
        if not self.client:
            await self.initialize()
        
        print("\n=== Echo DVM Test Client ===")
        print("Type your message to send to the Echo DVM")
        print("Type 'quit' to exit")
        print("Type 'status' to see pending requests")
        print()
        
        # Track current request for waiting
        current_request_event = None
        
        # Create notification handler
        class NotificationHandler(HandleNotification):
            def __init__(self, test_client):
                self.test_client = test_client
                self.response_received = asyncio.Event()

            async def handle(self, relay_url: str, subscription_id: str, event: Event):
                if event.kind().as_u16() == 25000:
                    await self.test_client.handle_response(event)
                    self.response_received.set()

            async def handle_msg(self, relay_url: str, msg: RelayMessage):
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
                    user_input = input("Enter message: ").strip()
                    
                    if user_input.lower() == 'quit':
                        break
                    elif user_input.lower() == 'status':
                        pending = [req for req in self.waiting_for_response.values() 
                                 if not req["completed"]]
                        print(f"Pending requests: {len(pending)}")
                        continue
                    elif not user_input:
                        continue
                    
                    # Reset the response event
                    handler.response_received.clear()
                    
                    # Send the job request
                    job_request = await self.send_job_request(user_input)
                    current_request_event = job_request
                    
                    # Show waiting message and wait for response
                    print("Waiting for response...")
                    
                    try:
                        # Wait for response with timeout
                        await asyncio.wait_for(handler.response_received.wait(), timeout=30.0)
                    except asyncio.TimeoutError:
                        print("⚠️  No response received within 30 seconds")
                    
                    print()  # Add spacing before next prompt
                    
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    print(f"Error: {e}")
        
        finally:
            notification_task.cancel()
            print("Test client shutting down...")
    
    async def send_single_test(self, message: str, target_dvm: Optional[str] = None):
        """Send a single test message and wait for response"""
        if not self.client:
            await self.initialize()
        
        # Start handling responses
        response_received = asyncio.Event()
        
        async def handle_notification(notification):
            if hasattr(notification, 'event'):
                event = notification.event
                if event.kind().as_u16() == 25000:
                    await self.handle_response(event)
                    response_received.set()
        
        # Start notification handler
        notification_task = asyncio.create_task(
            self.client.handle_notifications(handle_notification)
        )
        
        try:
            # Send the test message
            await self.send_job_request(message, target_dvm)
            
            # Wait for response (with timeout)
            try:
                await asyncio.wait_for(response_received.wait(), timeout=10.0)
            except asyncio.TimeoutError:
                print("Timeout waiting for response")
        
        finally:
            notification_task.cancel()

async def main():
    """Main function"""
    
    # Generate client keys (or load from environment)
    client_nsec = os.getenv("CLIENT_SECRET_KEY")
    if client_nsec:
        client_keys = Keys.parse(client_nsec)
    else:
        client_keys = Keys.generate()
        print(f"Generated client keys: {client_keys.secret_key().to_bech32()}")
    
    # Same relays as the DVM
    relay_urls = [
        "wss://relay.damus.io",
        "wss://nos.lol",
        "wss://relay.primal.net"
    ]
    
    # Create test client
    client = DVMTestClient(client_keys, relay_urls)
    
    # Check for command line arguments
    if len(sys.argv) > 1:
        # Single test mode
        message = " ".join(sys.argv[1:])
        target_dvm = os.getenv("TARGET_DVM_NPUB")
        if target_dvm:
            target_pubkey = PublicKey.from_bech32(target_dvm).to_hex()
        else:
            target_pubkey = None
        
        await client.send_single_test(message, target_pubkey)
    else:
        # Interactive mode
        await client.run_interactive_test()

if __name__ == "__main__":
    asyncio.run(main())
