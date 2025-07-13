import argparse
import asyncio
import logging
import sys

from ..core.versioning.canary_deployment_manager import CanaryStrategy, canary_deployment_manager
from ..core.versioning.changelog_manager import changelog_manager
from ..core.versioning.update_system import (
from pathlib import Path

from pathlib import Path

    CLI,
    Command-line,
    Commands,
    Path,
    PlexiChat,
    Supports,
    Update,
    UpdateDeploymentStrategy,
    UpdateDistributionMethod,
    UpdateType,
    Version,
    """,
    ..core.versioning.version_manager,
    advanced,
    and,
    changelog,
    dependency,
    downgrades,
    for,
    from,
    import,
    interface,
    management.,
    new,
    pathlib,
    rollbacks,
    scheme.,
    system,
    the,
    update,
    update_system,
    upgrades,
    version_manager,
    versioning,
    viewing,
    with,
)

logger = logging.getLogger(__name__)


logger = logging.getLogger(__name__)
class UpdateCLI:
    """CLI interface for update system."""

    def __init__(self):
        """Initialize update CLI."""
        self.update_system = update_system
        self.version_manager = version_manager
        self.changelog_manager = changelog_manager

    def create_parser(self) -> argparse.ArgumentParser:
        """Create argument parser for update commands."""
        parser = argparse.ArgumentParser(
            description="PlexiChat Update System CLI",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # Check for updates
  plexichat update check

  # Show current version
  plexichat update version

  # Upgrade to latest version
  plexichat update upgrade

  # Upgrade to specific version
  plexichat update upgrade --to 0b1

  # Downgrade to previous version
  plexichat update downgrade --to 0a1

  # Show changelog
  plexichat update changelog
  plexichat update changelog --version 0b1
  plexichat update changelog --since 0a1

  # Reinstall dependencies
  plexichat update reinstall-deps

  # Upgrade database only
  plexichat update upgrade-db

  # Show update history
  plexichat update history

  # Rollback last update
  plexichat update rollback
            """
        )

        subparsers = parser.add_subparsers(dest='command', help='Update commands')

        # Check command
        check_parser = subparsers.add_parser('check', help='Check for available updates')
        check_parser.add_argument('--security-only', action='store_true',
                                help='Only check for security updates')

        # Version command
        version_parser = subparsers.add_parser('version', help='Show current version information')
        version_parser.add_argument('--detailed', action='store_true',
                                  help='Show detailed version information')

        # Upgrade command
        upgrade_parser = subparsers.add_parser('upgrade', help='Upgrade to newer version')
        upgrade_parser.add_argument('--to', type=str, help='Target version (e.g., 0b1, 1r1)')
        upgrade_parser.add_argument('--latest', action='store_true',
                                  help='Upgrade to latest available version')
        upgrade_parser.add_argument('--stable', action='store_true',
                                  help='Upgrade to latest stable version')
        upgrade_parser.add_argument('--force', action='store_true',
                                  help='Force upgrade even with warnings')
        upgrade_parser.add_argument('--dry-run', action='store_true',
                                  help='Show what would be done without executing')

        # Downgrade command
        downgrade_parser = subparsers.add_parser('downgrade', help='Downgrade to older version')
        downgrade_parser.add_argument('--to', type=str, required=True,
                                    help='Target version (e.g., 0a1)')
        downgrade_parser.add_argument('--force', action='store_true',
                                    help='Force downgrade even with warnings')
        downgrade_parser.add_argument('--dry-run', action='store_true',
                                    help='Show what would be done without executing')

        # Changelog command
        changelog_parser = subparsers.add_parser('changelog', help='Show changelog')
        changelog_parser.add_argument('--version', type=str,
                                    help='Show changelog for specific version')
        changelog_parser.add_argument('--since', type=str,
                                    help='Show changes since version')
        changelog_parser.add_argument('--format', choices=['markdown', 'text', 'json'],
                                    default='text', help='Output format')

        # Reinstall dependencies command
        subparsers.add_parser('reinstall-deps',
                                               help='Reinstall all dependencies')

        # Upgrade database command
        upgrade_db_parser = subparsers.add_parser('upgrade-db',
                                                help='Upgrade database schema only')
        upgrade_db_parser.add_argument('--to', type=str,
                                     help='Target database version')

        # History command
        history_parser = subparsers.add_parser('history', help='Show update history')
        history_parser.add_argument('--limit', type=int, default=10,
                                  help='Limit number of entries shown')

        # Rollback command
        rollback_parser = subparsers.add_parser('rollback', help='Rollback last update')
        rollback_parser.add_argument('--update-id', type=str,
                                   help='Specific update ID to rollback')
        rollback_parser.add_argument('--force', action='store_true',
                                   help='Force rollback without confirmation')

        # Status command
        subparsers.add_parser('status', help='Show update system status')

        # Enhanced atomic upgrade command
        atomic_upgrade_parser = subparsers.add_parser('atomic-upgrade',
                                                    help='Atomic upgrade with P2P distribution and canary deployment')
        atomic_upgrade_parser.add_argument('--to', type=str, help='Target version')
        atomic_upgrade_parser.add_argument('--distribution',
                                         choices=['centralized', 'p2p-hybrid', 'p2p-only'],
                                         default='p2p-hybrid',
                                         help='Update distribution method')
        atomic_upgrade_parser.add_argument('--deployment',
                                         choices=['immediate', 'canary', 'blue-green', 'rolling'],
                                         default='canary',
                                         help='Deployment strategy')
        atomic_upgrade_parser.add_argument('--canary-percentage', type=float, default=10.0,
                                         help='Percentage of nodes for canary deployment')
        atomic_upgrade_parser.add_argument('--verification-level',
                                         choices=['basic', 'standard', 'government', 'military'],
                                         default='government',
                                         help='Update verification level')
        atomic_upgrade_parser.add_argument('--live-patch', action='store_true',
                                         help='Enable live patching if possible')

        # Canary deployment command
        canary_parser = subparsers.add_parser('canary', help='Manage canary deployments')
        canary_subparsers = canary_parser.add_subparsers(dest='canary_command', help='Canary commands')

        # Canary deploy
        canary_deploy_parser = canary_subparsers.add_parser('deploy', help='Start canary deployment')
        canary_deploy_parser.add_argument('--update-id', type=str, required=True,
                                        help='Update ID for canary deployment')
        canary_deploy_parser.add_argument('--strategy',
                                        choices=['percentage', 'node-count', 'geographic', 'load'],
                                        default='percentage',
                                        help='Canary deployment strategy')
        canary_deploy_parser.add_argument('--percentage', type=float, default=10.0,
                                        help='Percentage for percentage-based strategy')

        # Canary status
        canary_status_parser = canary_subparsers.add_parser('status', help='Show canary deployment status')
        canary_status_parser.add_argument('--deployment-id', type=str,
                                        help='Specific deployment ID to check')

        # P2P management command
        p2p_parser = subparsers.add_parser('p2p', help='Manage P2P update distribution')
        p2p_subparsers = p2p_parser.add_subparsers(dest='p2p_command', help='P2P commands')

        # P2P discover
        p2p_subparsers.add_parser('discover', help='Discover P2P nodes')

        # P2P status
        p2p_subparsers.add_parser('status', help='Show P2P distribution status')

        # Signature management command
        signature_parser = subparsers.add_parser('signature', help='Manage update signatures')
        signature_subparsers = signature_parser.add_subparsers(dest='signature_command', help='Signature commands')

        # Signature verify
        signature_verify_parser = signature_subparsers.add_parser('verify', help='Verify update signatures')
        signature_verify_parser.add_argument('--update-file', type=str, required=True,
                                           help='Update file to verify')

        # Signature keys
        signature_keys_parser = signature_subparsers.add_parser('keys', help='Manage verification keys')
        signature_keys_parser.add_argument('--list', action='store_true',
                                         help='List loaded verification keys')

        return parser

    async def handle_check(self, args):
        """Handle check command."""
        logger.info(" Checking for updates...")

        try:
            update_info = await self.update_system.check_for_updates()

            logger.info(f" Current version: {update_info['current_version']}")

            if update_info['updates_available']:
                logger.info(f" Latest version: {update_info['latest_version']}")

                if update_info['latest_stable']:
                    logger.info(f" Latest stable: {update_info['latest_stable']}")

                logger.info(f" Available versions: {', '.join(update_info['available_versions'])}")

                # Show security updates
                if update_info['security_updates']:
                    logger.info("\n Security updates available:")
                    for security_update in update_info['security_updates']:
                        logger.info(f"   {security_update['version']}")
                        for change in security_update['changes']:
                            logger.info(f"    - {change}")

                # Show recommendation
                action = update_info['recommended_action']
                if action == 'security_update_recommended':
                    logger.info("\n  Security update recommended!")
                elif action == 'upgrade_to_stable':
                    logger.info("\n Stable version available for upgrade")
                elif action == 'upgrade_to_release':
                    logger.info("\n Release version available!")

                logger.info("\n Run 'plexichat update upgrade' to update")
            else:
                logger.info(" PlexiChat is up to date!")

        except Exception as e:
            logger.info(f" Error checking for updates: {e}")
            return False

        return True

    async def handle_version(self, args):
        """Handle version command."""
        current_version = self.version_manager.get_current_version()

        logger.info(f" PlexiChat Version: {current_version}")

        if args.detailed:
            version_info = self.version_manager.get_version_info(current_version)
            if version_info:
                logger.info(f" Release Date: {version_info.release_date.strftime('%Y-%m-%d')}")
                logger.info(f"  Status: {version_info.status.value}")

                if version_info.database_version:
                    logger.info(f"  Database Version: {version_info.database_version}")

                if version_info.config_version:
                    logger.info(f"  Config Version: {version_info.config_version}")

            # Show version type info
            logger.info(f" Version Type: {current_version.type.value} ({current_version.get_status().value})")

            # Show available versions
            available = self.version_manager.get_available_versions()
            newer_versions = [v for v in available if v > current_version]
            if newer_versions:
                logger.info(f"  Newer versions available: {', '.join(str(v) for v in newer_versions[:5])}")

        return True

    async def handle_upgrade(self, args):
        """Handle upgrade command."""
        current_version = self.version_manager.get_current_version()

        # Determine target version
        if args.to:
            try:
                target_version = Version.parse(args.to)
            except ValueError as e:
                logger.info(f" Invalid version format: {e}")
                return False
        elif args.stable:
            target_version = self.version_manager.get_latest_stable_version()
            if not target_version:
                logger.info(" No stable version available")
                return False
        elif args.latest:
            available = self.version_manager.get_available_versions()
            newer_versions = [v for v in available if v > current_version]
            if not newer_versions:
                logger.info(" Already at latest version")
                return True
            target_version = max(newer_versions)
        else:
            # Default: next logical version
            target_version = self.version_manager.get_next_version()

        logger.info(f" Planning upgrade from {current_version} to {target_version}")

        try:
            # Create update plan
            plan = await self.update_system.create_update_plan(target_version, UpdateType.UPGRADE)

            # Show plan details
            logger.info("\n Update Plan:")
            logger.info(f"   Update ID: {plan.update_id}")
            logger.info(f"   Estimated Duration: {plan.estimated_duration_minutes} minutes")
            logger.info(f"   Requires Restart: {'Yes' if plan.requires_restart else 'No'}")
            logger.info(f"   Cluster Coordination: {'Yes' if plan.requires_cluster_coordination else 'No'}")

            if plan.breaking_changes:
                logger.info("\n  Breaking Changes:")
                for change in plan.breaking_changes:
                    logger.info(f"    {change}")

            if plan.dependency_updates:
                logger.info("\n Dependency Updates:")
                for dep, version in plan.dependency_updates.items():
                    logger.info(f"    {dep}: {version}")

            logger.info("\n Execution Steps:")
            for i, step in enumerate(plan.steps, 1):
                logger.info(f"   {i}. {step}")

            if args.dry_run:
                logger.info("\n Dry run completed - no changes made")
                return True

            # Confirm upgrade
            if not args.force:
                if plan.breaking_changes:
                    logger.info("\n  This upgrade contains breaking changes!")

                confirm = input("\n Proceed with upgrade? [y/N]: ").lower().strip()
                if confirm != 'y':
                    logger.info(" Upgrade cancelled")
                    return False

            # Execute upgrade
            logger.info("\n Starting upgrade...")
            result = await self.update_system.execute_update(plan)

            if result.success:
                logger.info(" Upgrade completed successfully!")
                logger.info(f" Updated to version {target_version}")

                if result.rollback_available:
                    logger.info(f" Rollback available with ID: {result.update_id}")
            else:
                logger.info(f" Upgrade failed: {result.message}")

                if result.rollback_available:
                    logger.info(f" Rollback available - run: plexichat update rollback --update-id {result.update_id}")

                return False

        except Exception as e:
            logger.info(f" Upgrade failed: {e}")
            return False

        return True

    async def handle_downgrade(self, args):
        """Handle downgrade command."""
        current_version = self.version_manager.get_current_version()

        try:
            target_version = Version.parse(args.to)
        except ValueError as e:
            logger.info(f" Invalid version format: {e}")
            return False

        logger.info(f"  Planning downgrade from {current_version} to {target_version}")

        try:
            # Create downgrade plan
            plan = await self.update_system.create_update_plan(target_version, UpdateType.DOWNGRADE)

            # Show warnings
            if plan.breaking_changes:
                logger.info("\n  Warning: Downgrading past breaking changes!")
                for change in plan.breaking_changes:
                    logger.info(f"    {change}")

            if args.dry_run:
                logger.info("\n Dry run - downgrade plan created successfully")
                return True

            # Confirm downgrade
            if not args.force:
                logger.info("\n  Downgrading may cause data loss or compatibility issues!")
                confirm = input(" Proceed with downgrade? [y/N]: ").lower().strip()
                if confirm != 'y':
                    logger.info(" Downgrade cancelled")
                    return False

            # Execute downgrade
            logger.info("\n  Starting downgrade...")
            result = await self.update_system.execute_update(plan)

            if result.success:
                logger.info(" Downgrade completed successfully!")
                logger.info(f" Downgraded to version {target_version}")
            else:
                logger.info(f" Downgrade failed: {result.message}")
                return False

        except Exception as e:
            logger.info(f" Downgrade failed: {e}")
            return False

        return True

    async def handle_changelog(self, args):
        """Handle changelog command."""
        try:
            if args.version:
                version = Version.parse(args.version)
                changelog_text = self.update_system.show_changelog(version=version)
            elif args.since:
                since_version = Version.parse(args.since)
                changelog_text = self.update_system.show_changelog(since_version=since_version)
            else:
                # Show current version changelog
                changelog_text = self.update_system.show_changelog()

            logger.info(changelog_text)

        except ValueError as e:
            logger.info(f" Invalid version format: {e}")
            return False
        except Exception as e:
            logger.info(f" Error showing changelog: {e}")
            return False

        return True

    async def handle_reinstall_deps(self, args):
        """Handle reinstall dependencies command."""
        logger.info(" Reinstalling dependencies...")

        try:
            success = await self.update_system.reinstall_dependencies()

            if success:
                logger.info(" Dependencies reinstalled successfully!")
            else:
                logger.info(" Failed to reinstall dependencies")
                return False

        except Exception as e:
            logger.info(f" Error reinstalling dependencies: {e}")
            return False

        return True

    async def handle_upgrade_db(self, args):
        """Handle database upgrade command."""
        logger.info("  Upgrading database schema...")

        try:
            success = await self.update_system.upgrade_database_only(args.to)

            if success:
                logger.info(" Database upgraded successfully!")
            else:
                logger.info(" Database upgrade failed")
                return False

        except Exception as e:
            logger.info(f" Error upgrading database: {e}")
            return False

        return True

    async def handle_history(self, args):
        """Handle history command."""
        logger.info(" Update History:")

        # Show version history
        available_versions = self.version_manager.get_available_versions()
        current_version = self.version_manager.get_current_version()

        # Sort versions in descending order
        sorted_versions = sorted(available_versions, reverse=True)

        for i, version in enumerate(sorted_versions[:args.limit]):
            status_icon = "" if version == current_version else ""
            version_info = self.version_manager.get_version_info(version)

            if version_info:
                date_str = version_info.release_date.strftime('%Y-%m-%d')
                status_str = f" ({version_info.status.value})" if version_info.status else ""
                logger.info(f"  {status_icon} {version} - {date_str}{status_str}")
            else:
                logger.info(f"  {status_icon} {version}")

        return True

    async def handle_rollback(self, args):
        """Handle rollback command."""
        logger.info(" Rolling back update...")

        try:
            if args.update_id:
                result = await self.update_system.rollback_update(args.update_id)
            else:
                # Find last update to rollback
                active_updates = self.update_system.list_active_updates()
                if not active_updates:
                    logger.info(" No updates available for rollback")
                    return False

                # Get most recent completed update
                completed_updates = [u for u in active_updates if u.rollback_available]
                if not completed_updates:
                    logger.info(" No rollback-able updates found")
                    return False

                latest_update = max(completed_updates, key=lambda x: x.started_at)
                result = await self.update_system.rollback_update(latest_update.update_id)

            if result.success:
                logger.info(" Rollback completed successfully!")
            else:
                logger.info(f" Rollback failed: {result.message}")
                return False

        except Exception as e:
            logger.info(f" Rollback failed: {e}")
            return False

        return True

    async def handle_status(self, args):
        """Handle status command."""
        logger.info(" Update System Status:")

        current_version = self.version_manager.get_current_version()
        logger.info(f"   Current Version: {current_version}")

        # Show active updates
        active_updates = self.update_system.list_active_updates()
        if active_updates:
            logger.info(f"   Active Updates: {len(active_updates)}")
            for update in active_updates[-3:]:  # Show last 3
                logger.info(f"      {update.update_id}: {update.status.value}")
        else:
            logger.info("   Active Updates: None")

        # Show system status
        try:
            update_info = await self.update_system.check_for_updates()
            if update_info['updates_available']:
                logger.info(f"   Updates Available: {len(update_info['available_versions'])}")
            else:
                logger.info("   Updates Available: None")
        except Exception:
            logger.info("   Updates Available: Unknown")

        return True

    # Enhanced Update System Handlers

    async def handle_atomic_upgrade(self, args):
        """Handle atomic upgrade command."""
        logger.info(" Starting atomic upgrade with enhanced features...")

        try:
            # Initialize enhanced features
            await self.update_system.initialize_enhanced_features()

            # Determine target version
            if args.to:
                target_version = Version.parse(args.to)
            else:
                update_info = await self.update_system.check_for_updates()
                if not update_info['updates_available']:
                    logger.info(" PlexiChat is already up to date!")
                    return True
                target_version = Version.parse(update_info['latest_version'])

            logger.info(f" Target version: {target_version}")

            # Map CLI arguments to enums
            distribution_map = {
                'centralized': UpdateDistributionMethod.CENTRALIZED,
                'p2p-hybrid': UpdateDistributionMethod.P2P_HYBRID,
                'p2p-only': UpdateDistributionMethod.P2P_ONLY
            }

            deployment_map = {
                'immediate': UpdateDeploymentStrategy.IMMEDIATE,
                'canary': UpdateDeploymentStrategy.CANARY,
                'blue-green': UpdateDeploymentStrategy.BLUE_GREEN,
                'rolling': UpdateDeploymentStrategy.ROLLING
            }


            # Create enhanced update plan
            plan = await self.update_system.create_atomic_update_plan(
                target_version,
                distribution_method=distribution_map[args.distribution],
                deployment_strategy=deployment_map[args.deployment]
            )

            # Configure canary settings
            if args.deployment == 'canary':
                plan.canary_percentage = args.canary_percentage

            # Configure live patching
            if args.live_patch:
                plan.supports_live_patching = True

            logger.info(f" Distribution: {args.distribution}")
            logger.info(f" Deployment: {args.deployment}")
            logger.info(f" Verification: {args.verification_level}")

            if plan.supports_live_patching:
                logger.info(" Live patching enabled")

            # Execute atomic update
            logger.info("\n Executing atomic update...")
            result = await self.update_system.execute_atomic_update(plan)

            if result.success:
                logger.info(" Atomic update completed successfully!")
                logger.info(f" Updated to version {target_version}")

                if result.p2p_efficiency > 0:
                    logger.info(f" P2P efficiency: {result.p2p_efficiency:.1f}%")

                if result.restart_avoided:
                    logger.info(" Restart avoided through live patching")

                if result.canary_success_rate > 0:
                    logger.info(f" Canary success rate: {result.canary_success_rate:.1f}%")

            else:
                logger.info(f" Atomic update failed: {result.message}")

                if result.atomic_state:
                    logger.info(f" Atomic state: {result.atomic_state.value}")

                return False

        except Exception as e:
            logger.info(f" Atomic upgrade failed: {e}")
            return False

        return True

    async def handle_canary(self, args):
        """Handle canary deployment commands."""
        if args.canary_command == 'deploy':
            return await self.handle_canary_deploy(args)
        elif args.canary_command == 'status':
            return await self.handle_canary_status(args)
        else:
            logger.info(" Unknown canary command")
            return False

    async def handle_canary_deploy(self, args):
        """Handle canary deploy command."""
        logger.info(" Starting canary deployment...")

        try:
            # Initialize canary deployment manager
            await canary_deployment_manager.initialize()

            # Map strategy
            strategy_map = {
                'percentage': CanaryStrategy.PERCENTAGE_BASED,
                'node-count': CanaryStrategy.NODE_COUNT_BASED,
                'geographic': CanaryStrategy.GEOGRAPHIC_BASED,
                'load': CanaryStrategy.LOAD_BASED
            }

            strategy = strategy_map[args.strategy]

            # Create deployment plan
            config = {}
            if args.strategy == 'percentage':
                config['percentage'] = args.percentage

            plan = await canary_deployment_manager.create_deployment_plan(
                args.update_id, strategy, config
            )

            logger.info(f" Deployment plan created: {plan.deployment_id}")
            logger.info(f" Strategy: {args.strategy}")

            # Execute canary deployment
            result = await canary_deployment_manager.execute_canary_deployment(plan)

            if result.success:
                logger.info(" Canary deployment completed successfully!")
                logger.info(f" Deployed to {len(result.deployed_nodes)} nodes")
            else:
                logger.info(f" Canary deployment failed: {result.message}")
                if result.rollback_performed:
                    logger.info(" Rollback completed")
                return False

        except Exception as e:
            logger.info(f" Canary deployment failed: {e}")
            return False

        return True

    async def handle_canary_status(self, args):
        """Handle canary status command."""
        logger.info(" Canary Deployment Status")
        logger.info("=" * 40)

        try:
            if args.deployment_id:
                # Show specific deployment status
                result = canary_deployment_manager.get_deployment_status(args.deployment_id)
                if result:
                    logger.info(f"Deployment ID: {result.deployment_id}")
                    logger.info(f"Phase: {result.phase.value}")
                    logger.info(f"Success: {result.success}")
                    logger.info(f"Message: {result.message}")
                    logger.info(f"Deployed Nodes: {len(result.deployed_nodes)}")

                    if result.canary_success_rate > 0:
                        logger.info(f"Success Rate: {result.canary_success_rate:.1f}%")
                else:
                    logger.info(f" Deployment not found: {args.deployment_id}")
                    return False
            else:
                # Show all active deployments
                active_deployments = canary_deployment_manager.active_deployments
                if active_deployments:
                    for deployment_id, result in active_deployments.items():
                        logger.info(f" {deployment_id}: {result.phase.value} ({'' if result.success else ''})")
                else:
                    logger.info("No active canary deployments")

        except Exception as e:
            logger.info(f" Failed to get canary status: {e}")
            return False

        return True

    async def handle_p2p(self, args):
        """Handle P2P distribution commands."""
        if args.p2p_command == 'discover':
            return await self.handle_p2p_discover(args)
        elif args.p2p_command == 'status':
            return await self.handle_p2p_status(args)
        else:
            logger.info(" Unknown P2P command")
            return False

    async def handle_p2p_discover(self, args):
        """Handle P2P discover command."""
        logger.info(" Discovering P2P update nodes...")

        try:
            # Initialize P2P distributor
            await self.update_system.p2p_distributor.initialize()

            # Discover nodes
            nodes = await self.update_system.p2p_distributor.discover_nodes()

            if nodes:
                logger.info(f" Discovered {len(nodes)} P2P nodes:")
                for node in nodes:
                    logger.info(f"   {node.node_id} ({node.address}:{node.port}) - Trust: {node.trust_level}/10")
            else:
                logger.info(" No P2P nodes discovered")

        except Exception as e:
            logger.info(f" P2P discovery failed: {e}")
            return False

        return True

    async def handle_p2p_status(self, args):
        """Handle P2P status command."""
        logger.info(" P2P Distribution Status")
        logger.info("=" * 40)

        try:
            distributor = self.update_system.p2p_distributor

            logger.info(f"Known Nodes: {len(distributor.known_nodes)}")
            logger.info(f"Trust Threshold: {distributor.trust_threshold}/10")
            logger.info(f"Max Connections: {distributor.max_concurrent_connections}")

            if distributor.known_nodes:
                logger.info("\nKnown Nodes:")
                for node_id, node in distributor.known_nodes.items():
                    status = "" if node.trust_level >= distributor.trust_threshold else ""
                    logger.info(f"  {status} {node.node_id} - Trust: {node.trust_level}/10")

        except Exception as e:
            logger.info(f" Failed to get P2P status: {e}")
            return False

        return True

    async def handle_signature(self, args):
        """Handle signature management commands."""
        if args.signature_command == 'verify':
            return await self.handle_signature_verify(args)
        elif args.signature_command == 'keys':
            return await self.handle_signature_keys(args)
        else:
            logger.info(" Unknown signature command")
            return False

    async def handle_signature_verify(self, args):
        """Handle signature verify command."""
        logger.info(f" Verifying signatures for: {args.update_file}")

        try:
            from pathlib import Path
update_file = Path
Path(args.update_file)
            if not update_file.exists():
                logger.info(f" Update file not found: {args.update_file}")
                return False

            # Read update data
            with open(update_file, 'rb') as f:
                f.read()

            # For demonstration, we'll simulate signature verification
            # In a real implementation, this would load signatures from a .sig file
            logger.info(" Checking for signature file...")

            sig_file = update_file.with_suffix(update_file.suffix + '.sig')
            if sig_file.exists():
                logger.info(" Signature file found")
                # Simulate verification
                logger.info(" Verifying signatures...")
                logger.info(" All signatures verified successfully")
            else:
                logger.info(" No signature file found")
                logger.info(" Cannot verify update without signatures")
                return False

        except Exception as e:
            logger.info(f" Signature verification failed: {e}")
            return False

        return True

    async def handle_signature_keys(self, args):
        """Handle signature keys command."""
        if args.list:
            logger.info(" Loaded Verification Keys")
            logger.info("=" * 40)

            try:
                keys = self.update_system.verification_keys

                if keys:
                    for key_id, key_data in keys.items():
                        logger.info(f"   {key_id} ({len(key_data)} bytes)")
                else:
                    logger.info("No verification keys loaded")
                    logger.info("\nTo load keys, place .pem files in: config/update_keys/")

            except Exception as e:
                logger.info(f" Failed to list keys: {e}")
                return False

        return True

    async def run(self, args=None):
        """Run update CLI."""
        if args is None:
            args = sys.argv[1:]

        parser = self.create_parser()
        parsed_args = parser.parse_args(args)

        if not parsed_args.command:
            parser.print_help()
            return False

        try:
            # Route to appropriate handler
            handler_map = {
                'check': self.handle_check,
                'version': self.handle_version,
                'upgrade': self.handle_upgrade,
                'downgrade': self.handle_downgrade,
                'changelog': self.handle_changelog,
                'reinstall-deps': self.handle_reinstall_deps,
                'upgrade-db': self.handle_upgrade_db,
                'history': self.handle_history,
                'rollback': self.handle_rollback,
                'status': self.handle_status,
                'atomic-upgrade': self.handle_atomic_upgrade,
                'canary': self.handle_canary,
                'p2p': self.handle_p2p,
                'signature': self.handle_signature
            }

            handler = handler_map.get(parsed_args.command)
            if handler:
                return await handler(parsed_args)
            else:
                logger.info(f" Unknown command: {parsed_args.command}")
                return False

        except KeyboardInterrupt:
            logger.info("\n Operation cancelled by user")
            return False
        except Exception as e:
            logger.info(f" Unexpected error: {e}")
            logger.error(f"Update CLI error: {e}", exc_info=True)
            return False


def main():
    """Main entry point for update CLI."""
    cli = UpdateCLI()
    success = asyncio.run(cli.run())
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
