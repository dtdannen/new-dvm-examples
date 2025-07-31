#!/usr/bin/env python3
"""
Simple Echo DVM - Returns whatever input it receives
"""

import asyncio
import os
from typing import Dict, List, Optional
from nostr_sdk import (
    Client, Keys, EventBuilder, Filter, Kind, Tag, Timestamp, 
    Event, HandleNotification, RelayMessage, NostrSigner, RelayUrl
)

class EchoDVM:
    """
    Simple DVM that echoes back whatever input it receives
    """
    
    def __init__(self, 
                 keys: Keys, 
                 relay_urls: List[str],
                 dvm_name: str = "Echo DVM",
                 category: str = "echo"):
        self.keys = keys
        self.relay_urls = relay_urls
        self.dvm_name = dvm_name
        self.category = category
        self.client = None
        
        # Track processed jobs to avoid duplicates
        self.processed_jobs = set()
        
        print(f"Initializing {dvm_name}")
        print(f"Category: {category}")
        print(f"DVM Public Key: {self.keys.public_key().to_bech32()}")
    
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
        
        # Subscribe to job requests
        await self.subscribe_to_job_requests()
    
    async def subscribe_to_job_requests(self):
        """Subscribe to DVM job requests"""
        # Create a single filter for kind 25000 events with category hashtag
        # This will catch both targeted and open requests
        job_filter = (Filter()
                     .kind(Kind(25000))
                     .hashtag(self.category)
                     .since(Timestamp.now()))
        
        subscription_id = await self.client.subscribe(job_filter)
        print(f"Subscribed to job requests for category '{self.category}': {subscription_id}")
    
    def extract_input_from_event(self, event: Event) -> str:
        """Extract input data from job request event"""
        # Look for 'i' tag (input tag)
        for tag in event.tags().to_vec():
            tag_vec = tag.as_vec()
            if len(tag_vec) >= 2 and tag_vec[0] == "i":
                return tag_vec[1]
        
        # Fallback to event content if no 'i' tag
        return event.content()
    
    def extract_job_params(self, event: Event) -> Dict[str, str]:
        """Extract job parameters from event tags"""
        params = {}
        for tag in event.tags().to_vec():
            tag_vec = tag.as_vec()
            if len(tag_vec) >= 3 and tag_vec[0] == "param":
                param_name = tag_vec[1]
                param_value = tag_vec[2]
                params[param_name] = param_value
        return params
    
    def is_job_request(self, event: Event) -> bool:
        """Check if this event is a job request (not a response)"""
        # If it tags another event, it's probably a response
        for tag in event.tags().to_vec():
            tag_vec = tag.as_vec()
            if len(tag_vec) >= 2 and tag_vec[0] == "e":
                return False
        
        # If it has input data, it's likely a request
        return bool(self.extract_input_from_event(event))
    
    async def process_job_request(self, event: Event) -> Optional[str]:
        """Process echo job - just return the input"""
        input_data = self.extract_input_from_event(event)
        if not input_data:
            return None
        
        print(f"Echoing: {input_data}")
        
        # Just echo back the input
        return f"Echo: {input_data}"
    
    async def send_job_result(self, 
                            original_event: Event, 
                            result: str, 
                            success: bool = True) -> Event:
        """Send job result using the same event kind"""
        
        # Create response tags
        tags = [
            Tag.parse(["e", original_event.id().to_hex()]),  # Reference original request
            Tag.parse(["p", original_event.author().to_hex()]),  # Tag the requester
            Tag.parse(["category", self.category]),  # Our service category
        ]
        
        if success:
            tags.append(Tag.parse(["status", "success"]))
        else:
            tags.append(Tag.parse(["status", "error"]))
        
        # Create the response event (same kind as request!)
        event_builder = EventBuilder(kind=Kind(25000), content=result)
        # Add tags using the tags method
        event_builder = event_builder.tags(tags)
        
        # Publish result
        await self.client.send_event_builder(event_builder)
        result_event = event_builder.build(self.keys.public_key())
        
        status_msg = "success" if success else "error"
        print(f"Sent {status_msg} result for job {original_event.id().to_hex()[:8]}")
        
        return result_event
    
    async def handle_job_request(self, event: Event):
        """Handle a single job request"""
        job_id = event.id().to_hex()
        
        # Skip if already processed
        if job_id in self.processed_jobs:
            return
        
        # Skip if this is a response, not a request
        if not self.is_job_request(event):
            return
        
        self.processed_jobs.add(job_id)
        
        print(f"\n=== Processing job request ===")
        print(f"Job ID: {job_id[:8]}")
        print(f"From: {event.author().to_bech32()}")
        print(f"Content: {event.content()}")
        
        try:
            # Process the job
            result = await self.process_job_request(event)
            
            if result is not None:
                # Send successful result
                await self.send_job_result(event, result, success=True)
                print(f"Successfully processed job: {result}")
            else:
                # Send error result
                await self.send_job_result(event, "Processing failed", success=False)
                print("Job processing failed")
                
        except Exception as e:
            print(f"Error processing job {job_id[:8]}: {e}")
            # Send error result
            await self.send_job_result(event, f"Error: {str(e)}", success=False)
        
        print("=== Job completed ===\n")
    
    async def run(self):
        """Main run loop for the DVM"""
        if not self.client:
            await self.initialize()
        
        print(f"\n{self.dvm_name} is now running and listening for job requests...")
        print("Press Ctrl+C to stop\n")
        
        # Create notification handler
        class NotificationHandler(HandleNotification):
            def __init__(self, dvm_instance):
                self.dvm_instance = dvm_instance

            async def handle(self, relay_url: str, subscription_id: str, event: Event):
                # Only process kind 25000 events (our job events)
                if event.kind().as_u16() == 25000:
                    await self.dvm_instance.handle_job_request(event)

            async def handle_msg(self, relay_url: str, msg: RelayMessage):
                # Handle relay messages if needed (currently just pass)
                pass
        
        handler = NotificationHandler(self)
        
        # Start handling notifications
        await self.client.handle_notifications(handler)

async def main():
    """Main function to run the Echo DVM"""
    
    # Load keys from environment or generate new ones
    nsec = os.getenv("DVM_SECRET_KEY")
    if not nsec:
        # Generate new keys for testing
        keys = Keys.generate()
        nsec = keys.secret_key().to_bech32()
        print(f"Generated new keys. Set environment variable:")
        print(f"export DVM_SECRET_KEY='{nsec}'")
        print()
    else:
        keys = Keys.parse(nsec)
    
    # Define relay URLs
    relay_urls = [
        "wss://relay.damus.io",
        "wss://nos.lol",
        "wss://relay.primal.net"
    ]
    
    # Create and run the Echo DVM
    dvm = EchoDVM(keys, relay_urls)
    
    try:
        await dvm.run()
    except KeyboardInterrupt:
        print("\nShutting down Echo DVM...")

if __name__ == "__main__":
    asyncio.run(main())
