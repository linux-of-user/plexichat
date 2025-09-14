import argparse
import asyncio
import logging

# Integrate with the real cluster manager implementation
from plexichat.core.clustering.cluster_manager import (
    ClusterConfiguration,
    ClusterNode,
    NodeMetrics,
    NodeStatus,
    NodeType,
    get_cluster_manager,
)

logger = logging.getLogger(__name__)


class ClusterCLI:
    """Command-line interface for cluster management."""

    def __init__(self):
        self.cluster_manager = get_cluster_manager()
        self.parser = self._create_parser()

    def _create_parser(self) -> argparse.ArgumentParser:
        """Creates the argument parser for cluster commands."""
        parser = argparse.ArgumentParser(description="PlexiChat Cluster Management")
        subparsers = parser.add_subparsers(
            dest="command", help="Cluster commands", required=True
        )

        # Status
        status_parser = subparsers.add_parser("status", help="Show cluster status")
        status_parser.add_argument(
            "--detailed", action="store_true", help="Show detailed status"
        )

        # List nodes
        list_parser = subparsers.add_parser("list", help="List cluster nodes")
        list_parser.add_argument(
            "--healthy", action="store_true", help="Only show healthy nodes"
        )
        list_parser.add_argument(
            "--type",
            type=str,
            help="Filter by node type (networking, endpoint, general, cache, database, load_balancer)",
        )

        # Add node
        add_parser = subparsers.add_parser(
            "add-node", help="Add/register a new node to the cluster"
        )
        add_parser.add_argument(
            "--node-id", required=True, help="Unique node identifier"
        )
        add_parser.add_argument(
            "--hostname", required=True, help="Hostname of the node"
        )
        add_parser.add_argument("--ip", required=True, help="IP address of the node")
        add_parser.add_argument(
            "--port", type=int, default=8000, help="Port of the node"
        )
        add_parser.add_argument("--type", default="general", help="Node type")
        add_parser.add_argument(
            "--region", default="default", help="Geographical region"
        )
        add_parser.add_argument("--zone", default="default", help="Availability zone")
        add_parser.add_argument(
            "--weight", type=float, default=1.0, help="Load balancing weight"
        )
        add_parser.add_argument(
            "--capabilities",
            default="",
            help="Comma-separated capabilities (api, websocket, clustering, cache, db)",
        )

        # Remove node
        remove_parser = subparsers.add_parser(
            "remove-node", help="Remove/unregister a node from the cluster"
        )
        remove_parser.add_argument("--node-id", required=True, help="Node ID to remove")

        # Initialize local node / start manager
        init_parser = subparsers.add_parser(
            "init-local",
            help="Initialize/start local cluster manager and register local node",
        )

        # Health check
        health_parser = subparsers.add_parser(
            "health-check", help="Trigger a health check immediately"
        )

        # Failover test
        failover_parser = subparsers.add_parser(
            "failover-test", help="Simulate a node failure to test failover"
        )
        failover_parser.add_argument(
            "--node-id", required=True, help="Node ID to simulate failure for"
        )

        # Scale cluster
        scale_parser = subparsers.add_parser(
            "scale", help="Scale cluster to target number of nodes"
        )
        scale_parser.add_argument(
            "--target", type=int, required=True, help="Target number of nodes"
        )

        # Rebalance cluster
        rebalance_parser = subparsers.add_parser(
            "rebalance", help="Rebalance cluster distribution"
        )

        # Config get/set
        cfg_get_parser = subparsers.add_parser(
            "config-get", help="Get cluster configuration value"
        )
        cfg_get_parser.add_argument(
            "--key", required=False, help="Specific configuration key to get (optional)"
        )

        cfg_set_parser = subparsers.add_parser(
            "config-set", help="Set cluster configuration value"
        )
        cfg_set_parser.add_argument(
            "--key", required=True, help="Configuration key to set"
        )
        cfg_set_parser.add_argument(
            "--value", required=True, help="New value for the configuration key"
        )

        # Sync config
        sync_parser = subparsers.add_parser(
            "sync-config", help="Force synchronization of configuration to all nodes"
        )

        # Update node metrics
        metrics_parser = subparsers.add_parser(
            "update-metrics", help="Update metrics for a node"
        )
        metrics_parser.add_argument(
            "--node-id", required=True, help="Node ID for which to update metrics"
        )
        metrics_parser.add_argument(
            "--cpu", type=float, default=0.0, help="CPU usage percent"
        )
        metrics_parser.add_argument(
            "--memory", type=float, default=0.0, help="Memory usage percent"
        )
        metrics_parser.add_argument(
            "--disk", type=float, default=0.0, help="Disk usage percent"
        )
        metrics_parser.add_argument(
            "--latency", type=float, default=0.0, help="Network latency ms"
        )
        metrics_parser.add_argument(
            "--request-rate", type=float, default=0.0, help="Request rate"
        )
        metrics_parser.add_argument(
            "--error-rate", type=float, default=0.0, help="Error rate (0-1)"
        )
        metrics_parser.add_argument(
            "--uptime", type=int, default=0, help="Uptime seconds"
        )

        # Shutdown manager
        shutdown_parser = subparsers.add_parser(
            "shutdown", help="Stop cluster manager gracefully"
        )

        return parser

    async def run(self, args: list[str]):
        """Runs the cluster CLI."""
        parsed_args = self.parser.parse_args(args)

        # Ensure manager started for operations that need running state
        command = parsed_args.command

        try:
            if command in (
                "init-local",
                "status",
                "list",
                "add-node",
                "remove-node",
                "health-check",
                "failover-test",
                "scale",
                "rebalance",
                "config-get",
                "config-set",
                "sync-config",
                "update-metrics",
                "shutdown",
            ):
                # Start the manager if not running for commands that interact with cluster state
                if not getattr(self.cluster_manager, "running", False):
                    logger.info("Starting cluster manager for CLI operation...")
                    await self.cluster_manager.start()

            if command == "status":
                await self.handle_status(parsed_args)
            elif command == "list":
                await self.handle_list(parsed_args)
            elif command == "add-node":
                await self.handle_add_node(parsed_args)
            elif command == "remove-node":
                await self.handle_remove_node(parsed_args)
            elif command == "init-local":
                await self.handle_init_local(parsed_args)
            elif command == "health-check":
                await self.handle_health_check(parsed_args)
            elif command == "failover-test":
                await self.handle_failover_test(parsed_args)
            elif command == "scale":
                await self.handle_scale(parsed_args)
            elif command == "rebalance":
                await self.handle_rebalance(parsed_args)
            elif command == "config-get":
                await self.handle_config_get(parsed_args)
            elif command == "config-set":
                await self.handle_config_set(parsed_args)
            elif command == "sync-config":
                await self.handle_sync_config(parsed_args)
            elif command == "update-metrics":
                await self.handle_update_metrics(parsed_args)
            elif command == "shutdown":
                await self.handle_shutdown(parsed_args)
            else:
                self.parser.print_help()
        except Exception as e:
            logger.error(f"Error executing command '{command}': {e}")

    async def handle_status(self, args: argparse.Namespace):
        """Handles the 'status' command."""
        logger.info("Fetching cluster status...")
        status = await self.cluster_manager.get_cluster_status()

        # If detailed, include node listing and per-node metrics
        if getattr(args, "detailed", False):
            nodes = await self.cluster_manager.get_all_nodes()
            status["nodes"] = [
                {
                    "node_id": n.node_id,
                    "address": n.address,
                    "type": (
                        n.node_type.value
                        if hasattr(n.node_type, "value")
                        else str(n.node_type)
                    ),
                    "status": (
                        n.status.value if hasattr(n.status, "value") else str(n.status)
                    ),
                    "region": n.region,
                    "zone": n.zone,
                    "weight": n.weight,
                    "capabilities": list(n.capabilities),
                    "metrics": {
                        "cpu": n.metrics.cpu_usage,
                        "memory": n.metrics.memory_usage,
                        "disk": n.metrics.disk_usage,
                        "latency": n.metrics.network_latency,
                        "request_rate": n.metrics.request_rate,
                        "error_rate": n.metrics.error_rate,
                        "uptime_seconds": n.metrics.uptime_seconds,
                    },
                    "last_heartbeat": (
                        n.last_heartbeat.isoformat() if n.last_heartbeat else None
                    ),
                    "joined_at": (
                        n.joined_at.isoformat() if hasattr(n, "joined_at") else None
                    ),
                }
                for n in nodes
            ]

        # Print status
        for key, value in status.items():
            logger.info(f"- {key.replace('_', ' ').title()}: {value}")

    async def handle_list(self, args: argparse.Namespace):
        """List nodes in the cluster."""
        node_type_filter = None
        if getattr(args, "type", None):
            try:
                node_type_filter = NodeType(args.type.lower())
            except Exception:
                logger.warning(f"Unknown node type '{args.type}' - ignoring filter")

        nodes = await self.cluster_manager.get_all_nodes()
        if getattr(args, "healthy", False):
            nodes = [
                n for n in nodes if n.node_id in self.cluster_manager.healthy_nodes
            ]

        if node_type_filter:
            nodes = [n for n in nodes if n.node_type == node_type_filter]

        if not nodes:
            logger.info("No nodes found in cluster.")
            return

        for n in nodes:
            logger.info(
                f"- {n.node_id} | {n.address} | type={n.node_type.value} | status={n.status.value} | weight={n.weight} | caps={','.join(n.capabilities)}"
            )

    async def handle_add_node(self, args: argparse.Namespace):
        """Add/register a new node to the cluster."""
        caps: set[str] = set()
        if getattr(args, "capabilities", ""):
            caps = set(c.strip() for c in args.capabilities.split(",") if c.strip())

        # Resolve node type
        node_type = NodeType.GENERAL
        try:
            node_type = NodeType(args.type.lower())
        except Exception:
            logger.warning(f"Invalid node type '{args.type}', defaulting to 'general'")

        node = ClusterNode(
            node_id=args.node_id,
            hostname=args.hostname,
            ip_address=args.ip,
            port=int(args.port),
            node_type=node_type,
            status=NodeStatus.STARTING,
            region=args.region,
            zone=args.zone,
            weight=float(args.weight),
            capabilities=caps,
            metadata={"added_via_cli": True},
        )

        success = await self.cluster_manager.register_node(node)
        if success:
            logger.info(f"Node {args.node_id} registered successfully.")
        else:
            logger.error(f"Failed to register node {args.node_id}.")

    async def handle_remove_node(self, args: argparse.Namespace):
        """Remove/unregister a node from the cluster."""
        node_id = args.node_id
        success = await self.cluster_manager.unregister_node(node_id)
        if success:
            logger.info(f"Node {node_id} removed successfully.")
        else:
            logger.error(f"Failed to remove node {node_id}.")

    async def handle_init_local(self, args: argparse.Namespace):
        """Initialize local node (ensure manager is running and local node registered)."""
        # start() was called earlier in run(), but ensure local node id exists
        if not getattr(self.cluster_manager, "local_node_id", None):
            # start() will run _initialize_local_node as part of starting
            logger.info("Initializing local node...")
            await self.cluster_manager.start()

        local_id = getattr(self.cluster_manager, "local_node_id", None)
        logger.info(f"Local node initialized: {local_id}")

    async def handle_health_check(self, args: argparse.Namespace):
        """Trigger an immediate health check."""
        logger.info("Triggering immediate health check...")
        # Use internal method to perform health checks once
        # It's acceptable here to call the internal method for CLI diagnostics
        if hasattr(self.cluster_manager, "_perform_health_checks"):
            await self.cluster_manager._perform_health_checks()
            logger.info("Health check completed.")
            status = await self.cluster_manager.get_cluster_status()
            logger.info(f"Cluster health: {status.get('status')}")
        else:
            logger.error(
                "Cluster manager does not support health checks in this deployment."
            )

    async def handle_failover_test(self, args: argparse.Namespace):
        """Simulate a node failure to test failover behavior."""
        node_id = args.node_id
        node = await self.cluster_manager.get_node(node_id)
        if not node:
            logger.error(f"Node {node_id} not found.")
            return

        logger.info(f"Simulating failure for node {node_id}...")
        # Mark as failed and invoke failure handler
        node.status = NodeStatus.FAILED
        await self.cluster_manager._handle_node_failure(node_id)
        logger.info(f"Failover simulation executed for node {node_id}.")

    async def handle_scale(self, args: argparse.Namespace):
        """Scale cluster to target nodes."""
        target = int(args.target)
        result = await self.cluster_manager.scale_cluster(target)
        if result.get("success"):
            logger.info(f"Scale operation submitted: {result}")
        else:
            logger.error(f"Scale operation failed: {result}")

    async def handle_rebalance(self, args: argparse.Namespace):
        """Rebalance the cluster."""
        result = await self.cluster_manager.rebalance_cluster()
        if result.get("success"):
            logger.info("Rebalance completed successfully.")
        else:
            logger.error(f"Rebalance failed: {result}")

    async def handle_config_get(self, args: argparse.Namespace):
        """Get cluster configuration or a specific key."""
        cfg: ClusterConfiguration = self.cluster_manager.config
        if getattr(args, "key", None):
            key = args.key
            value = getattr(cfg, key, None)
            logger.info(f"{key} = {value}")
        else:
            # Print whole config as key: value pairs
            for field_name in [
                "cluster_id",
                "cluster_name",
                "min_nodes",
                "max_nodes",
                "replication_factor",
                "health_check_interval",
                "heartbeat_timeout",
                "auto_scaling_enabled",
                "load_balancing_strategy",
                "failover_enabled",
                "backup_enabled",
                "encryption_enabled",
                "version",
            ]:
                logger.info(f"{field_name} = {getattr(cfg, field_name, None)}")

    async def handle_config_set(self, args: argparse.Namespace):
        """Set cluster configuration key/value."""
        cfg: ClusterConfiguration = self.cluster_manager.config
        key = args.key
        value = args.value

        if not hasattr(cfg, key):
            logger.error(f"Configuration key '{key}' not found.")
            return

        # Attempt to cast to the correct type based on current value type
        current = getattr(cfg, key)
        try:
            if isinstance(current, bool):
                new_value = value.lower() in ("1", "true", "yes", "on")
            elif isinstance(current, int):
                new_value = int(value)
            elif isinstance(current, float):
                new_value = float(value)
            else:
                new_value = value
            setattr(cfg, key, new_value)
            # Update timestamp if present
            if hasattr(cfg, "updated_at"):
                import datetime

                cfg.updated_at = datetime.datetime.now(datetime.UTC)
            logger.info(f"Configuration '{key}' updated to '{new_value}'.")
            # Optionally sync immediately
            if hasattr(self.cluster_manager, "_sync_config_to_all_nodes"):
                await self.cluster_manager._sync_config_to_all_nodes()
                logger.info("Configuration synchronized to all nodes.")
        except Exception as e:
            logger.error(f"Failed to set configuration key '{key}': {e}")

    async def handle_sync_config(self, args: argparse.Namespace):
        """Force synchronization of configuration to all nodes."""
        if hasattr(self.cluster_manager, "_sync_config_to_all_nodes"):
            await self.cluster_manager._sync_config_to_all_nodes()
            logger.info("Configuration synchronized to all nodes.")
        else:
            logger.error(
                "Cluster manager does not support config synchronization in this deployment."
            )

    async def handle_update_metrics(self, args: argparse.Namespace):
        """Update metrics for a node."""
        node_id = args.node_id
        metrics = NodeMetrics(
            cpu_usage=float(args.cpu),
            memory_usage=float(args.memory),
            disk_usage=float(args.disk),
            network_latency=float(args.latency),
            request_rate=float(getattr(args, "request_rate", 0.0)),
            error_rate=float(getattr(args, "error_rate", 0.0)),
            uptime_seconds=int(getattr(args, "uptime", 0)),
        )
        success = await self.cluster_manager.update_node_metrics(node_id, metrics)
        if success:
            logger.info(f"Metrics updated for node {node_id}.")
        else:
            logger.error(f"Failed to update metrics for {node_id}.")

    async def handle_shutdown(self, args: argparse.Namespace):
        """Shutdown the cluster manager gracefully."""
        logger.info("Shutting down cluster manager...")
        await self.cluster_manager.stop()
        logger.info("Cluster manager stopped.")


async def handle_cluster_command(args: list[str]):
    """Handle cluster CLI commands."""
    cli = ClusterCLI()
    await cli.run(args)


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO)
    if len(sys.argv) > 1:
        asyncio.run(handle_cluster_command(sys.argv[1:]))
    else:
        # Example of how to run, or print help
        cli = ClusterCLI()
        cli.parser.print_help()
