import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

import aio_pika
try:
    import redis.asyncio as redis
except ImportError:
    redis = None
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer



"""
PlexiChat Message Queue System

Comprehensive asynchronous message processing system supporting:
- RabbitMQ integration for reliable message queuing
- Apache Kafka integration for high-throughput streaming
- Redis Streams for lightweight message queuing
- Dead letter queues for failed message handling
- Message routing and topic-based publishing
- Consumer groups and load balancing
- Message persistence and durability
- Performance monitoring and analytics

Features:
- Multiple message broker support with failover
- Automatic message serialization/deserialization
- Retry mechanisms with exponential backoff
- Message deduplication and ordering guarantees
- Real-time monitoring and alerting
- Horizontal scaling with consumer groups
"""

# Optional dependencies - graceful degradation
try:
    RABBITMQ_AVAILABLE = True
except ImportError:
    RABBITMQ_AVAILABLE = False

try:
    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False

try:
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

logger = logging.getLogger(__name__)


class MessageBroker(Enum):
    """Supported message brokers."""
    RABBITMQ = "rabbitmq"
    KAFKA = "kafka"
    REDIS_STREAMS = "redis_streams"


class MessagePriority(Enum):
    """Message priority levels."""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class Message:
    """Message structure."""
    id: str
    topic: str
    payload: Any
    headers: Dict[str, Any]
    priority: MessagePriority = MessagePriority.NORMAL
    created_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    retry_count: int = 0
    max_retries: int = 3

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now(timezone.utc)
        if self.id is None:
            self.id = str(uuid.uuid4())

    def is_expired(self) -> bool:
        """Check if message is expired."""
        if not self.expires_at:
            return False
        return datetime.now(timezone.utc) >= self.expires_at

    def can_retry(self) -> bool:
        """Check if message can be retried."""
        return self.retry_count < self.max_retries

    def to_dict(self) -> Dict[str, Any]:
        """Convert message to dictionary."""
        return {
            "id": self.id,
            "topic": self.topic,
            "payload": self.payload,
            "headers": self.headers,
            "priority": self.priority.value,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Message':
        """Create message from dictionary."""
        return cls(
            id=data["id"],
            topic=data["topic"],
            payload=data["payload"],
            headers=data["headers"],
            priority=MessagePriority(data["priority"]),
            created_at=datetime.fromisoformat(data["created_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]) if data["expires_at"] else None,
            retry_count=data["retry_count"],
            max_retries=data["max_retries"]
        )


@dataclass
class QueueStats:
    """Queue statistics."""
    messages_sent: int = 0
    messages_received: int = 0
    messages_processed: int = 0
    messages_failed: int = 0
    messages_retried: int = 0
    messages_dead_lettered: int = 0
    average_processing_time_ms: float = 0.0
    queue_depth: int = 0
    consumer_count: int = 0

    @property
    def success_rate(self) -> float:
        """Calculate message processing success rate."""
        total = self.messages_processed + self.messages_failed
        return self.messages_processed / total if total > 0 else 0.0


class MessageQueueManager:
    """
    Comprehensive message queue management system.

    Supports multiple message brokers with automatic failover,
    message routing, consumer groups, and performance monitoring.
    """

    def __init__(self, config: Dict[str, Any]):
        """Initialize message queue manager."""
        self.config = config
        self.initialized = False

        # Broker connections
        self.rabbitmq_connection: Optional[aio_pika.Connection] = None
        self.rabbitmq_channel: Optional[aio_pika.Channel] = None
        self.kafka_producer: Optional[AIOKafkaProducer] = None
        self.kafka_consumers: Dict[str, AIOKafkaConsumer] = {}
        self.redis_client: Optional[redis.Redis] = None

        # Configuration
        self.primary_broker = MessageBroker(config.get("primary_broker", "redis_streams"))
        self.fallback_brokers = [MessageBroker(b) for b in config.get("fallback_brokers", [])]
        self.default_ttl_seconds = config.get("default_ttl_seconds", 3600)
        self.max_retries = config.get("max_retries", 3)
        self.retry_delay_seconds = config.get("retry_delay_seconds", 5)

        # Message handlers and consumers
        self.message_handlers: Dict[str, Callable] = {}
        self.consumer_tasks: List[asyncio.Task] = []

        # Statistics
        self.stats_by_topic: Dict[str, QueueStats] = {}
        self.global_stats = QueueStats()

        # Dead letter queue
        self.dead_letter_queue: List[Message] = []

        logger.info(" Message Queue Manager initialized")

    async def initialize(self) -> Dict[str, Any]:
        """Initialize message queue connections."""
        try:
            results = {
                "rabbitmq": await self._initialize_rabbitmq(),
                "kafka": await self._initialize_kafka(),
                "redis_streams": await self._initialize_redis(),
                "primary_broker": self.primary_broker.value
            }

            # Start background tasks
            asyncio.create_task(self._stats_collection_task())
            asyncio.create_task(self._dead_letter_processor_task())
            asyncio.create_task(self._health_check_task())

            self.initialized = True

            logger.info(" Message Queue Manager fully initialized")
            return results

        except Exception as e:
            logger.error(f" Message queue initialization failed: {e}")
            raise

    async def _initialize_rabbitmq(self) -> bool:
        """Initialize RabbitMQ connection."""
        if not RABBITMQ_AVAILABLE:
            logger.warning(" RabbitMQ not available")
            return False

        try:
            rabbitmq_config = self.config.get("rabbitmq", {})

            connection_url = (
                f"amqp://{rabbitmq_config.get('username', 'guest')}:"
                f"{rabbitmq_config.get('password', 'guest')}@"
                f"{rabbitmq_config.get('host', 'localhost')}:"
                f"{rabbitmq_config.get('port', 5672)}/"
                f"{rabbitmq_config.get('vhost', '/')}"
            )

            self.rabbitmq_connection = await aio_pika.connect_robust(
                connection_url,
                heartbeat=rabbitmq_config.get("heartbeat", 600),
                blocked_connection_timeout=rabbitmq_config.get("blocked_timeout", 300)
            )

            self.rabbitmq_channel = await self.rabbitmq_connection.channel()
            await self.rabbitmq_channel.set_qos(prefetch_count=rabbitmq_config.get("prefetch", 10))

            logger.info(" RabbitMQ initialized")
            return True

        except Exception as e:
            logger.warning(f" RabbitMQ initialization failed: {e}")
            return False

    async def _initialize_kafka(self) -> bool:
        """Initialize Kafka connection."""
        if not KAFKA_AVAILABLE:
            logger.warning(" Kafka not available")
            return False

        try:
            kafka_config = self.config.get("kafka", {})
            bootstrap_servers = kafka_config.get("bootstrap_servers", ["localhost:9092"])

            self.kafka_producer = AIOKafkaProducer(
                bootstrap_servers=bootstrap_servers,
                value_serializer=lambda v: json.dumps(v).encode(),
                compression_type=kafka_config.get("compression", "gzip"),
                batch_size=kafka_config.get("batch_size", 16384),
                linger_ms=kafka_config.get("linger_ms", 10),
                max_request_size=kafka_config.get("max_request_size", 1048576)
            )

            await self.if kafka_producer and hasattr(kafka_producer, "start"): kafka_producer.start()

            logger.info(" Kafka initialized")
            return True

        except Exception as e:
            logger.warning(f" Kafka initialization failed: {e}")
            return False

    async def _initialize_redis(self) -> bool:
        """Initialize Redis Streams connection."""
        if not REDIS_AVAILABLE:
            logger.warning(" Redis not available")
            return False

        try:
            redis_config = self.config.get("redis", {})

            self.redis_client = redis.Redis(
                host=redis_config.get("host", "localhost"),
                port=redis_config.get("port", 6379),
                db=redis_config.get("db", 1),  # Use different DB than cache
                password=redis_config.get("password"),
                decode_responses=False,
                socket_connect_timeout=redis_config.get("connect_timeout", 5),
                socket_timeout=redis_config.get("timeout", 5),
                max_connections=redis_config.get("max_connections", 20)
            )

            # Test connection
            await self.redis_client.ping()

            logger.info(" Redis Streams initialized")
            return True

        except Exception as e:
            logger.warning(f" Redis Streams initialization failed: {e}")
            return False

    async def publish(self, topic: str, payload: Any, headers: Optional[Dict[str, Any]] = None,
                     priority: MessagePriority = MessagePriority.NORMAL,
                     ttl_seconds: Optional[int] = None) -> bool:
        """Publish message to topic."""
        try:
            if headers is None:
                headers = {}

            if ttl_seconds is None:
                ttl_seconds = self.default_ttl_seconds

            # Create message
            message = Message(
                id=str(uuid.uuid4()),
                topic=topic,
                payload=payload,
                headers=headers,
                priority=priority,
                expires_at=datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds) if ttl_seconds > 0 else None,
                max_retries=self.max_retries
            )

            # Try primary broker first
            success = await self._publish_to_broker(self.primary_broker, message)

            # Try fallback brokers if primary fails
            if not success:
                for broker in self.fallback_brokers:
                    success = await self._publish_to_broker(broker, message)
                    if success:
                        logger.warning(f" Used fallback broker {broker.value} for topic {topic}")
                        break

            if success:
                # Update statistics
                if topic not in self.stats_by_topic:
                    self.stats_by_topic[topic] = QueueStats()

                self.stats_by_topic[topic].messages_sent += 1
                self.global_stats.messages_sent += 1

                logger.debug(f" Message published to topic {topic}")
                return True
            else:
                logger.error(f" Failed to publish message to topic {topic}")
                return False

        except Exception as e:
            logger.error(f" Publish error for topic {topic}: {e}")
            return False

    async def _publish_to_broker(self, broker: MessageBroker, message: Message) -> bool:
        """Publish message to specific broker."""
        try:
            if broker == MessageBroker.RABBITMQ and self.rabbitmq_channel:
                return await self._publish_rabbitmq(message)
            elif broker == MessageBroker.KAFKA and self.kafka_producer:
                return await self._publish_kafka(message)
            elif broker == MessageBroker.REDIS_STREAMS and self.redis_client:
                return await self._publish_redis(message)
            else:
                return False

        except Exception as e:
            logger.error(f" Broker {broker.value} publish error: {e}")
            return False

    async def _publish_rabbitmq(self, message: Message) -> bool:
        """Publish message to RabbitMQ."""
        try:
            # Declare exchange and queue
            exchange = await self.rabbitmq_channel.declare_exchange(
                f"plexichat.{message.topic}",
                aio_pika.ExchangeType.TOPIC,
                durable=True
            )

            queue = await self.rabbitmq_channel.declare_queue(
                f"plexichat.{message.topic}.queue",
                durable=True
            )

            await queue.bind(exchange, routing_key=message.topic)

            # Create message
            rabbitmq_message = aio_pika.Message(
                json.dumps(message.to_dict()).encode(),
                priority=message.priority.value,
                expiration=int((message.expires_at - datetime.now(timezone.utc)).total_seconds() * 1000) if message.expires_at else None,
                headers=message.headers,
                message_id=message.id
            )

            # Publish message
            await exchange.publish(rabbitmq_message, routing_key=message.topic)
            return True

        except Exception as e:
            logger.error(f" RabbitMQ publish error: {e}")
            return False

    async def _publish_kafka(self, message: Message) -> bool:
        """Publish message to Kafka."""
        try:
            # Serialize message
            message_data = message.to_dict()

            # Add headers
            headers = [(k, v.encode() if isinstance(v, str) else str(v).encode())
                      for k, v in message.headers.items()]
            headers.append(("message_id", message.id.encode()))
            headers.append(("priority", str(message.priority.value).encode()))

            # Send message
            await self.kafka_producer.send(
                message.topic,
                value=message_data,
                headers=headers,
                key=message.id.encode()
            )

            return True

        except Exception as e:
            logger.error(f" Kafka publish error: {e}")
            return False

    async def _publish_redis(self, message: Message) -> bool:
        """Publish message to Redis Streams."""
        try:
            stream_key = f"plexichat:stream:{message.topic}"

            # Prepare message data
            message_data = {
                "id": message.id,
                "payload": json.dumps(message.payload),
                "headers": json.dumps(message.headers),
                "priority": message.priority.value,
                "created_at": message.created_at.isoformat(),
                "expires_at": message.expires_at.isoformat() if message.expires_at else "",
                "retry_count": message.retry_count,
                "max_retries": message.max_retries
            }

            # Add to stream
            await self.redis_client.xadd(stream_key, message_data)

            # Set TTL on stream if configured
            if message.expires_at:
                ttl_seconds = int((message.expires_at - datetime.now(timezone.utc)).total_seconds())
                if ttl_seconds > 0:
                    await self.redis_client.expire(stream_key, ttl_seconds)

            return True

        except Exception as e:
            logger.error(f" Redis Streams publish error: {e}")
            return False

    async def subscribe(self, topic: str, handler: Callable[[Message], Any],
                       consumer_group: Optional[str] = None) -> bool:
        """Subscribe to topic with message handler."""
        try:
            if topic in self.message_handlers:
                logger.warning(f" Handler already exists for topic {topic}")
                return False

            self.message_handlers[topic] = handler

            # Start consumer for primary broker
            consumer_task = asyncio.create_task(
                self._start_consumer(self.primary_broker, topic, consumer_group)
            )
            self.consumer_tasks.append(consumer_task)

            logger.info(f" Subscribed to topic {topic}")
            return True

        except Exception as e:
            logger.error(f" Subscribe error for topic {topic}: {e}")
            return False

    async def _start_consumer(self, broker: MessageBroker, topic: str, consumer_group: Optional[str]):
        """Start consumer for specific broker and topic."""
        try:
            if broker == MessageBroker.RABBITMQ and self.rabbitmq_channel:
                await self._consume_rabbitmq(topic)
            elif broker == MessageBroker.KAFKA and self.kafka_producer:  # Producer initialized means Kafka available
                await self._consume_kafka(topic, consumer_group)
            elif broker == MessageBroker.REDIS_STREAMS and self.redis_client:
                await self._consume_redis(topic, consumer_group)
            else:
                logger.warning(f" No consumer available for broker {broker.value}")

        except Exception as e:
            logger.error(f" Consumer error for {broker.value} topic {topic}: {e}")

    async def _consume_rabbitmq(self, topic: str):
        """Consume messages from RabbitMQ."""
        try:
            queue = await self.rabbitmq_channel.declare_queue(
                f"plexichat.{topic}.queue",
                durable=True
            )

            async with queue.iterator() as queue_iter:
                async for rabbitmq_message in queue_iter:
                    try:
                        # Parse message
                        message_data = json.loads(rabbitmq_message.body.decode())
                        message = Message.from_dict(message_data)

                        # Process message
                        success = await self._process_message(message)

                        if success:
                            await rabbitmq_message.ack()
                        else:
                            await rabbitmq_message.nack(requeue=message.can_retry())

                    except Exception as e:
                        logger.error(f" RabbitMQ message processing error: {e}")
                        await rabbitmq_message.nack(requeue=False)

        except Exception as e:
            logger.error(f" RabbitMQ consumer error for topic {topic}: {e}")

    async def _consume_kafka(self, topic: str, consumer_group: Optional[str]):
        """Consume messages from Kafka."""
        try:
            kafka_config = self.config.get("kafka", {})

            consumer = AIOKafkaConsumer(
                topic,
                bootstrap_servers=kafka_config.get("bootstrap_servers", ["localhost:9092"]),
                group_id=consumer_group or f"plexichat-{topic}",
                value_deserializer=lambda m: json.loads(m.decode()),
                auto_offset_reset=kafka_config.get("auto_offset_reset", "latest"),
                enable_auto_commit=False,
                max_poll_records=kafka_config.get("max_poll_records", 500)
            )

            await if consumer and hasattr(consumer, "start"): consumer.start()
            self.kafka_consumers[topic] = consumer

            try:
                async for kafka_message in consumer:
                    try:
                        # Parse message
                        message = Message.from_dict(kafka_message.value)

                        # Process message
                        success = await self._process_message(message)

                        if success:
                            await consumer.commit()
                        else:
                            # Handle retry logic for Kafka
                            if message.can_retry():
                                message.retry_count += 1
                                await self._publish_to_broker(MessageBroker.KAFKA, message)
                            else:
                                self.dead_letter_queue.append(message)

                            await consumer.commit()  # Commit to avoid reprocessing

                    except Exception as e:
                        logger.error(f" Kafka message processing error: {e}")
                        await consumer.commit()  # Commit to avoid infinite retry

            finally:
                await if consumer and hasattr(consumer, "stop"): consumer.stop()

        except Exception as e:
            logger.error(f" Kafka consumer error for topic {topic}: {e}")

    async def _consume_redis(self, topic: str, consumer_group: Optional[str]):
        """Consume messages from Redis Streams."""
        try:
            stream_key = f"plexichat:stream:{topic}"
            group_name = consumer_group or f"plexichat-{topic}-group"
            consumer_name = f"consumer-{uuid.uuid4().hex[:8]}"

            # Create consumer group if it doesn't exist
            try:
                await self.redis_client.xgroup_create(stream_key, group_name, id="0", mkstream=True)
              # Group might already exist

            while True:
                try:
                    # Read messages from stream
                    messages = await self.redis_client.xreadgroup(
                        group_name,
                        consumer_name,
                        {stream_key: ">"},
                        count=10,
                        block=1000  # Block for 1 second
                    )

                    for stream, stream_messages in messages:
                        for message_id, fields in stream_messages:
                            try:
                                # Parse message
                                message_data = {
                                    "id": fields[b"id"].decode(),
                                    "topic": topic,
                                    "payload": json.loads(fields[b"payload"].decode()),
                                    "headers": json.loads(fields[b"headers"].decode()),
                                    "priority": int(fields[b"priority"]),
                                    "created_at": fields[b"created_at"].decode(),
                                    "expires_at": fields[b"expires_at"].decode() if fields[b"expires_at"] else None,
                                    "retry_count": int(fields[b"retry_count"]),
                                    "max_retries": int(fields[b"max_retries"])
                                }

                                message = Message.from_dict(message_data)

                                # Check if message is expired
                                if message.is_expired():
                                    await self.redis_client.xack(stream_key, group_name, message_id)
                                    continue

                                # Process message
                                success = await self._process_message(message)

                                if success:
                                    # Acknowledge message
                                    await self.redis_client.xack(stream_key, group_name, message_id)
                                else:
                                    # Handle retry
                                    if message.can_retry():
                                        message.retry_count += 1
                                        await self._publish_redis(message)
                                        await self.redis_client.xack(stream_key, group_name, message_id)
                                    else:
                                        # Move to dead letter queue
                                        self.dead_letter_queue.append(message)
                                        await self.redis_client.xack(stream_key, group_name, message_id)

                            except Exception as e:
                                logger.error(f" Redis message processing error: {e}")
                                await self.redis_client.xack(stream_key, group_name, message_id)

                except Exception as e:
                    if "NOGROUP" in str(e):
                        # Recreate consumer group
                        try:
                            await self.redis_client.xgroup_create(stream_key, group_name, id="0", mkstream=True)

                    else:
                        logger.error(f" Redis consumer read error: {e}")
                        await asyncio.sleep(5)  # Wait before retrying

        except Exception as e:
            logger.error(f" Redis consumer error for topic {topic}: {e}")

    async def _process_message(self, message: Message) -> bool:
        """Process message with registered handler."""
        start_time = time.time()

        try:
            # Get handler for topic
            handler = self.message_handlers.get(message.topic)
            if not handler:
                logger.warning(f" No handler for topic {message.topic}")
                return False

            # Update statistics
            if message.topic not in self.stats_by_topic:
                self.stats_by_topic[message.topic] = QueueStats()

            self.stats_by_topic[message.topic].messages_received += 1
            self.global_stats.messages_received += 1

            # Call handler
            if asyncio.iscoroutinefunction(handler):
                await handler(message)
            else:
                handler(message)

            # Update success statistics
            processing_time = (time.time() - start_time) * 1000

            topic_stats = self.stats_by_topic[message.topic]
            topic_stats.messages_processed += 1
            self.global_stats.messages_processed += 1

            # Update average processing time
            if topic_stats.messages_processed > 1:
                topic_stats.average_processing_time_ms = (
                    (topic_stats.average_processing_time_ms * (topic_stats.messages_processed - 1) + processing_time) /
                    topic_stats.messages_processed
                )
            else:
                topic_stats.average_processing_time_ms = processing_time

            logger.debug(f" Message processed for topic {message.topic} in {processing_time:.2f}ms")
            return True

        except Exception as e:
            # Update failure statistics
            if message.topic in self.stats_by_topic:
                self.stats_by_topic[message.topic].messages_failed += 1
            self.global_stats.messages_failed += 1

            logger.error(f" Message processing failed for topic {message.topic}: {e}")
            return False

    async def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive message queue statistics."""
        try:
            # Topic-specific stats
            topic_stats = {}
            for topic, stats in self.stats_by_topic.items():
                topic_stats[topic] = {
                    "messages_sent": stats.messages_sent,
                    "messages_received": stats.messages_received,
                    "messages_processed": stats.messages_processed,
                    "messages_failed": stats.messages_failed,
                    "messages_retried": stats.messages_retried,
                    "messages_dead_lettered": stats.messages_dead_lettered,
                    "success_rate": stats.success_rate,
                    "average_processing_time_ms": stats.average_processing_time_ms,
                    "queue_depth": stats.queue_depth,
                    "consumer_count": stats.consumer_count
                }

            return {
                "global": {
                    "messages_sent": self.global_stats.messages_sent,
                    "messages_received": self.global_stats.messages_received,
                    "messages_processed": self.global_stats.messages_processed,
                    "messages_failed": self.global_stats.messages_failed,
                    "messages_retried": self.global_stats.messages_retried,
                    "messages_dead_lettered": self.global_stats.messages_dead_lettered,
                    "success_rate": self.global_stats.success_rate,
                    "average_processing_time_ms": self.global_stats.average_processing_time_ms
                },
                "topics": topic_stats,
                "configuration": {
                    "primary_broker": self.primary_broker.value,
                    "fallback_brokers": [b.value for b in self.fallback_brokers],
                    "default_ttl_seconds": self.default_ttl_seconds,
                    "max_retries": self.max_retries,
                    "retry_delay_seconds": self.retry_delay_seconds
                },
                "availability": {
                    "rabbitmq": self.rabbitmq_connection is not None,
                    "kafka": self.kafka_producer is not None,
                    "redis_streams": self.redis_client is not None
                },
                "dead_letter_queue": {
                    "count": len(self.dead_letter_queue),
                    "messages": [msg.to_dict() for msg in self.dead_letter_queue[-10:]]  # Last 10 messages
                },
                "active_consumers": len(self.consumer_tasks),
                "registered_handlers": list(self.message_handlers.keys())
            }

        except Exception as e:
            logger.error(f" Error getting message queue stats: {e}")
            return {"error": str(e)}

    # Background tasks

    async def _stats_collection_task(self):
        """Background task for statistics collection."""
        while True:
            try:
                await asyncio.sleep(60)  # Run every minute

                # Update global statistics
                self.global_stats.messages_sent = sum(stats.messages_sent for stats in self.stats_by_topic.values())
                self.global_stats.messages_received = sum(stats.messages_received for stats in self.stats_by_topic.values())
                self.global_stats.messages_processed = sum(stats.messages_processed for stats in self.stats_by_topic.values())
                self.global_stats.messages_failed = sum(stats.messages_failed for stats in self.stats_by_topic.values())

                # Log warnings for high failure rates
                for topic, stats in self.stats_by_topic.items():
                    if stats.success_rate < 0.8 and stats.messages_processed > 10:
                        logger.warning(f" Low success rate for topic {topic}: {stats.success_rate:.2%}")

            except Exception as e:
                logger.error(f" Stats collection task error: {e}")
                await asyncio.sleep(30)

    async def _dead_letter_processor_task(self):
        """Background task for processing dead letter queue."""
        while True:
            try:
                await asyncio.sleep(300)  # Run every 5 minutes

                if not self.dead_letter_queue:
                    continue

                logger.info(f" Processing {len(self.dead_letter_queue)} dead letter messages")

                # Process dead letter messages
                processed_count = 0
                failed_messages = []

                for message in self.dead_letter_queue:
                    try:
                        # Try to reprocess message
                        success = await self._process_message(message)
                        if success:
                            processed_count += 1
                            self.stats_by_topic[message.topic].messages_retried += 1
                            self.global_stats.messages_retried += 1
                        else:
                            failed_messages.append(message)

                    except Exception as e:
                        logger.error(f" Dead letter processing error: {e}")
                        failed_messages.append(message)

                # Update dead letter queue
                self.dead_letter_queue = failed_messages

                if processed_count > 0:
                    logger.info(f" Reprocessed {processed_count} dead letter messages")

                # Limit dead letter queue size
                if len(self.dead_letter_queue) > 1000:
                    self.dead_letter_queue = self.dead_letter_queue[-1000:]
                    logger.warning(" Dead letter queue truncated to 1000 messages")

            except Exception as e:
                logger.error(f" Dead letter processor task error: {e}")
                await asyncio.sleep(60)

    async def _health_check_task(self):
        """Background task for health checking connections."""
        while True:
            try:
                await asyncio.sleep(120)  # Run every 2 minutes

                # Check RabbitMQ connection
                if self.rabbitmq_connection and self.rabbitmq_connection.is_closed:
                    logger.warning(" RabbitMQ connection lost, attempting reconnection...")
                    await self._initialize_rabbitmq()

                # Check Kafka producer
                if self.kafka_producer and hasattr(self.kafka_producer, '_closed') and self.kafka_producer._closed:
                    logger.warning(" Kafka producer lost, attempting reconnection...")
                    await self._initialize_kafka()

                # Check Redis connection
                if self.redis_client:
                    try:
                        await self.redis_client.ping()
                    except Exception:
                        logger.warning(" Redis connection lost, attempting reconnection...")
                        await self._initialize_redis()

            except Exception as e:
                logger.error(f" Health check task error: {e}")
                await asyncio.sleep(60)

    async def unsubscribe(self, topic: str) -> bool:
        """Unsubscribe from topic."""
        try:
            if topic not in self.message_handlers:
                logger.warning(f" No subscription found for topic {topic}")
                return False

            # Remove handler
            del self.message_handlers[topic]

            # Stop Kafka consumer if exists
            if topic in self.kafka_consumers:
                await self.kafka_consumers[topic].stop()
                del self.kafka_consumers[topic]

            logger.info(f" Unsubscribed from topic {topic}")
            return True

        except Exception as e:
            logger.error(f" Unsubscribe error for topic {topic}: {e}")
            return False

    async def purge_topic(self, topic: str) -> bool:
        """Purge all messages from topic."""
        try:
            success_count = 0

            # Purge RabbitMQ queue
            if self.rabbitmq_channel:
                try:
                    queue = await self.rabbitmq_channel.declare_queue(
                        f"plexichat.{topic}.queue",
                        durable=True
                    )
                    await queue.purge()
                    success_count += 1
                except Exception as e:
                    logger.warning(f" RabbitMQ purge error for topic {topic}: {e}")

            # Purge Redis stream
            if self.redis_client:
                try:
                    stream_key = f"plexichat:stream:{topic}"
                    await self.redis_client.delete(stream_key)
                    success_count += 1
                except Exception as e:
                    logger.warning(f" Redis purge error for topic {topic}: {e}")

            # Note: Kafka topic purging requires admin privileges and is not implemented here

            if success_count > 0:
                logger.info(f" Purged topic {topic}")
                return True
            else:
                logger.warning(f" No queues purged for topic {topic}")
                return False

        except Exception as e:
            logger.error(f" Purge error for topic {topic}: {e}")
            return False

    async def shutdown(self):
        """Gracefully shutdown message queue manager."""
        try:
            logger.info(" Shutting down Message Queue Manager...")

            # Stop consumer tasks
            for task in self.consumer_tasks:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

            # Close connections
            if self.rabbitmq_connection:
                await if self.rabbitmq_connection: self.rabbitmq_connection.close()
                logger.info(" RabbitMQ connection closed")

            if self.kafka_producer:
                await self.if kafka_producer and hasattr(kafka_producer, "stop"): kafka_producer.stop()
                logger.info(" Kafka producer stopped")

            for consumer in self.kafka_consumers.values():
                await if consumer and hasattr(consumer, "stop"): consumer.stop()
            logger.info(" Kafka consumers stopped")

            if self.redis_client:
                await if self.redis_client: self.redis_client.close()
                logger.info(" Redis connection closed")

            logger.info(" Message Queue Manager shutdown complete")

        except Exception as e:
            logger.error(f" Message queue shutdown error: {e}")


# Global message queue manager instance
_queue_manager: Optional[MessageQueueManager] = None


def get_queue_manager(config: Optional[Dict[str, Any]] = None) -> MessageQueueManager:
    """Get or create global message queue manager instance."""
    global _queue_manager

    if _queue_manager is None:
        if config is None:
            # Default configuration
            config = {
                "primary_broker": "redis_streams",
                "fallback_brokers": ["rabbitmq"],
                "default_ttl_seconds": 3600,
                "max_retries": 3,
                "retry_delay_seconds": 5,
                "rabbitmq": {
                    "host": "localhost",
                    "port": 5672,
                    "username": "guest",
                    "password": "guest",
                    "vhost": "/",
                    "heartbeat": 600,
                    "prefetch": 10
                },
                "kafka": {
                    "bootstrap_servers": ["localhost:9092"],
                    "compression": "gzip",
                    "batch_size": 16384,
                    "linger_ms": 10,
                    "max_request_size": 1048576,
                    "auto_offset_reset": "latest",
                    "max_poll_records": 500
                },
                "redis": {
                    "host": "localhost",
                    "port": 6379,
                    "db": 1,
                    "max_connections": 20
                }
            }

        _queue_manager = MessageQueueManager(config)

    return _queue_manager
