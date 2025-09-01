#!/usr/bin/env python3
"""
Test script for threads functionality
"""

import asyncio
import sys
import os

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'src')))

async def test_threads():
    """Test thread functionality directly."""
    try:
        from plexichat.core.messaging.unified_messaging_system import get_messaging_system
        from plexichat.core.messaging.unified_messaging_system import MessageType

        print("Testing threads functionality...")

        # Get messaging system
        messaging_system = get_messaging_system()
        print("[OK] Messaging system obtained")

        # Test creating a thread
        print("\n1. Testing thread creation...")
        success, thread_id_or_error, thread = await messaging_system.create_thread(
            title="Test Thread",
            channel_id="test_channel",
            creator_id="test_user",
            parent_message_id=None
        )

        if success:
            print(f"[OK] Thread created successfully: {thread_id_or_error}")
            print(f"  Thread ID: {thread.thread_id}")
            print(f"  Title: {thread.title}")
            print(f"  Channel: {thread.channel_id}")
            print(f"  Creator: {thread.creator_id}")
        else:
            print(f"[FAIL] Thread creation failed: {thread_id_or_error}")
            return

        # Test getting the thread
        print("\n2. Testing thread retrieval...")
        retrieved_thread = messaging_system.get_thread(thread_id_or_error)
        if retrieved_thread:
            print(f"[OK] Thread retrieved successfully: {retrieved_thread.title}")
        else:
            print("[FAIL] Thread retrieval failed")

        # Test sending a message in the thread
        print("\n3. Testing thread message sending...")
        msg_success, msg_id_or_error, message = await messaging_system.send_thread_message(
            sender_id="test_user",
            thread_id=thread_id_or_error,
            content="Test message in thread",
            message_type=MessageType.TEXT,
            reply_to=None
        )

        if msg_success:
            print(f"[OK] Thread message sent successfully: {msg_id_or_error}")
        else:
            print(f"[FAIL] Thread message sending failed: {msg_id_or_error}")

        # Test getting thread messages
        print("\n4. Testing thread messages retrieval...")
        messages = await messaging_system.get_thread_messages(
            thread_id=thread_id_or_error,
            limit=10,
            before_message_id=None
        )

        if messages:
            print(f"[OK] Retrieved {len(messages)} thread messages")
            for msg in messages:
                print(f"  - {msg.metadata.message_id}: {msg.content[:50]}...")
        else:
            print("[FAIL] No thread messages retrieved")

        # Test getting channel threads
        print("\n5. Testing channel threads retrieval...")
        channel_threads = messaging_system.get_channel_threads("test_channel")
        if channel_threads:
            print(f"[OK] Retrieved {len(channel_threads)} threads for channel")
            for t in channel_threads:
                print(f"  - {t.thread_id}: {t.title}")
        else:
            print("[FAIL] No channel threads retrieved")

        print("\n[SUCCESS] All thread tests completed successfully!")

    except Exception as e:
        print(f"[ERROR] Test failed with error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_threads())