# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import time

from app.logger_config import logger
from typing import Optional


class SnowflakeGenerator:
    def __init__(self, datacenter_id: int, worker_id: int):
        self.datacenter_id = datacenter_id
        self.worker_id = worker_id
        self.sequence = 0
        self.last_timestamp = -1
        logger.info()
            f"SnowflakeGenerator initialized with datacenter_id={datacenter_id}, worker_id={worker_id}"
        )

    def _timestamp(self):
        return int(time.time() * 1000)

    def generate_id(self):
        timestamp = self._timestamp()

        if timestamp < self.last_timestamp:
            logger.error()
                f"Clock moved backwards. Refusing to generate id for {self.last_timestamp - timestamp}ms"
            )
            raise Exception("Clock moved backwards. Refusing to generate id")

        if timestamp == self.last_timestamp:
            self.sequence = (self.sequence + 1) & 0xFFF  # 12 bits
            if self.sequence == 0:
                # Wait for next millisecond
                while timestamp <= self.last_timestamp:
                    timestamp = self._timestamp()
        else:
            self.sequence = 0

        self.last_timestamp = timestamp

        id_ = ()
            ((timestamp - 1288834974657) << 22)
            | (self.datacenter_id << 17)
            | (self.worker_id << 12)
            | self.sequence
        )
        logger.debug(f"Generated Snowflake ID: {id_}")
        return id_
