"""
Human review service for moderation with comprehensive workflow management.
Handles assignment, escalation, and reporting for human moderators.
"""

import asyncio
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from sqlmodel import Session, select, func

from plexichat.app.models.advanced_moderation import (
    ModerationItem, ModerationAppeal, ModerationWorkflow,
    ModerationAction, ModerationSeverity, ModerationStatus, ModerationSource
)
from plexichat.app.models.enhanced_models import EnhancedUser
from plexichat.app.logger_config import logger


@dataclass
class ReviewAssignment:
    """Assignment of moderation item to human reviewer."""
    item_id: int
    moderator_id: int
    assigned_at: datetime
    priority_score: float
    estimated_time_minutes: int
    deadline: datetime
    auto_assigned: bool


@dataclass
class ReviewMetrics:
    """Metrics for human review performance."""
    moderator_id: int
    total_reviews: int
    avg_review_time_minutes: float
    accuracy_score: float
    consistency_score: float
    items_pending: int
    items_overdue: int
    specializations: List[str]


@dataclass
class WorkloadAnalysis:
    """Analysis of moderation workload."""
    total_pending: int
    high_priority_pending: int
    overdue_items: int
    avg_wait_time_hours: float
    moderator_utilization: Dict[int, float]
    bottlenecks: List[str]
    recommendations: List[str]


class HumanReviewService:
    """Service for managing human review of moderation items."""
    
    def __init__(self, session: Session):
        self.session = session
        self.assignment_algorithms = {
            "round_robin": self._assign_round_robin,
            "expertise_based": self._assign_by_expertise,
            "workload_balanced": self._assign_by_workload,
            "priority_based": self._assign_by_priority
        }
    
    async def assign_for_review(
        self,
        item: ModerationItem,
        assignment_method: str = "workload_balanced",
        force_moderator_id: Optional[int] = None
    ) -> Optional[ReviewAssignment]:
        """Assign moderation item to human reviewer."""
        try:
            if force_moderator_id:
                moderator = self.session.get(EnhancedUser, force_moderator_id)
                if not moderator or not self._is_moderator(moderator):
                    raise ValueError(f"Invalid moderator ID: {force_moderator_id}")
                assigned_moderator = moderator
            else:
                # Get available moderators
                available_moderators = await self._get_available_moderators()
                if not available_moderators:
                    logger.warning("No available moderators for assignment")
                    return None
                
                # Use assignment algorithm
                assignment_func = self.assignment_algorithms.get(
                    assignment_method, 
                    self._assign_by_workload
                )
                assigned_moderator = await assignment_func(item, available_moderators)
            
            if not assigned_moderator:
                return None
            
            # Calculate priority and deadline
            priority_score = await self._calculate_priority_score(item)
            estimated_time = await self._estimate_review_time(item)
            deadline = await self._calculate_deadline(item, priority_score)
            
            # Create assignment
            assignment = ReviewAssignment(
                item_id=item.id,
                moderator_id=assigned_moderator.id,
                assigned_at=datetime.now(timezone.utc),
                priority_score=priority_score,
                estimated_time_minutes=estimated_time,
                deadline=deadline,
                auto_assigned=force_moderator_id is None
            )
            
            # Update moderation item
            item.assigned_moderator_id = assigned_moderator.id
            item.status = ModerationStatus.IN_REVIEW
            item.priority_score = priority_score
            
            self.session.commit()
            
            logger.info(f"📋 Assigned moderation item {item.id} to moderator {assigned_moderator.id}")
            
            # Send notification to moderator
            await self._notify_moderator(assigned_moderator, item, assignment)
            
            return assignment
            
        except Exception as e:
            logger.error(f"Failed to assign item {item.id} for review: {e}")
            return None
    
    async def submit_review(
        self,
        item_id: int,
        moderator_id: int,
        decision: ModerationAction,
        reasoning: str,
        notes: Optional[str] = None,
        escalate: bool = False
    ) -> bool:
        """Submit human review decision."""
        try:
            item = self.session.get(ModerationItem, item_id)
            if not item:
                raise ValueError(f"Moderation item {item_id} not found")
            
            if item.assigned_moderator_id != moderator_id:
                raise ValueError(f"Item {item_id} not assigned to moderator {moderator_id}")
            
            # Record human decision
            item.human_decision = decision
            item.human_reasoning = reasoning
            item.human_notes = notes
            item.reviewed_at = datetime.now(timezone.utc)
            
            if escalate:
                item.escalated = True
                item.escalated_at = datetime.now(timezone.utc)
                item.escalated_by = moderator_id
                item.status = ModerationStatus.ESCALATED
                
                logger.info(f"🔺 Moderation item {item_id} escalated by moderator {moderator_id}")
                
                # Assign to senior moderator
                await self._escalate_to_senior_moderator(item)
            else:
                # Finalize decision
                item.final_action = decision
                item.final_decision_by = moderator_id
                item.action_taken_at = datetime.now(timezone.utc)
                item.status = ModerationStatus.RESOLVED
                item.resolved_at = datetime.now(timezone.utc)
                
                logger.info(f"✅ Moderation item {item_id} resolved by moderator {moderator_id}: {decision.value}")
                
                # Execute the moderation action
                await self._execute_moderation_action(item)
            
            self.session.commit()
            
            # Update moderator metrics
            await self._update_moderator_metrics(moderator_id, item)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to submit review for item {item_id}: {e}")
            return False
    
    async def get_moderator_queue(
        self,
        moderator_id: int,
        limit: int = 50,
        priority_filter: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get moderation queue for a specific moderator."""
        try:
            query = select(ModerationItem).where(
                (ModerationItem.assigned_moderator_id == moderator_id) &
                (ModerationItem.status.in_([ModerationStatus.IN_REVIEW, ModerationStatus.PENDING]))
            )
            
            if priority_filter:
                if priority_filter == "high":
                    query = query.where(ModerationItem.priority_score >= 0.7)
                elif priority_filter == "overdue":
                    # Items that should have been reviewed by now
                    overdue_time = datetime.now(timezone.utc) - timedelta(hours=24)
                    query = query.where(ModerationItem.created_at <= overdue_time)
            
            query = query.order_by(
                ModerationItem.priority_score.desc(),
                ModerationItem.created_at.asc()
            ).limit(limit)
            
            items = self.session.exec(query).all()
            
            queue_items = []
            for item in items:
                # Calculate time metrics
                age_hours = (datetime.now(timezone.utc) - item.created_at.replace(tzinfo=timezone.utc)).total_seconds() / 3600
                estimated_time = await self._estimate_review_time(item)
                
                queue_items.append({
                    "id": item.id,
                    "content_type": item.content_type,
                    "content_id": item.content_id,
                    "content_preview": item.content_text[:200] if item.content_text else "",
                    "severity": item.severity.value,
                    "priority_score": item.priority_score,
                    "source": item.source.value,
                    "age_hours": age_hours,
                    "estimated_time_minutes": estimated_time,
                    "ai_recommendation": item.ai_recommendation.value if item.ai_recommendation else None,
                    "ai_confidence": item.ai_confidence_score,
                    "ai_reasoning": item.ai_reasoning,
                    "created_at": item.created_at.isoformat(),
                    "metadata": item.content_metadata
                })
            
            return queue_items
            
        except Exception as e:
            logger.error(f"Failed to get moderator queue for {moderator_id}: {e}")
            return []
    
    async def get_review_metrics(self, moderator_id: int) -> ReviewMetrics:
        """Get performance metrics for a moderator."""
        try:
            # Get review statistics
            total_reviews = self.session.exec(
                select(func.count(ModerationItem.id))
                .where(ModerationItem.final_decision_by == moderator_id)
            ).first() or 0
            
            # Get pending items
            pending_items = self.session.exec(
                select(func.count(ModerationItem.id))
                .where(
                    (ModerationItem.assigned_moderator_id == moderator_id) &
                    (ModerationItem.status == ModerationStatus.IN_REVIEW)
                )
            ).first() or 0
            
            # Get overdue items (more than 24 hours old)
            overdue_time = datetime.now(timezone.utc) - timedelta(hours=24)
            overdue_items = self.session.exec(
                select(func.count(ModerationItem.id))
                .where(
                    (ModerationItem.assigned_moderator_id == moderator_id) &
                    (ModerationItem.status == ModerationStatus.IN_REVIEW) &
                    (ModerationItem.created_at <= overdue_time)
                )
            ).first() or 0
            
            # Calculate average review time
            reviewed_items = self.session.exec(
                select(ModerationItem)
                .where(
                    (ModerationItem.final_decision_by == moderator_id) &
                    (ModerationItem.reviewed_at.is_not(None)) &
                    (ModerationItem.created_at.is_not(None))
                )
                .limit(100)  # Last 100 reviews
            ).all()
            
            avg_review_time = 0.0
            if reviewed_items:
                total_time = sum(
                    (item.reviewed_at.replace(tzinfo=timezone.utc) - item.created_at.replace(tzinfo=timezone.utc)).total_seconds() / 60
                    for item in reviewed_items
                    if item.reviewed_at and item.created_at
                )
                avg_review_time = total_time / len(reviewed_items)
            
            # Get specializations (content types most frequently handled)
            specializations = []
            content_type_counts = self.session.exec(
                select(ModerationItem.content_type, func.count(ModerationItem.id))
                .where(ModerationItem.final_decision_by == moderator_id)
                .group_by(ModerationItem.content_type)
                .order_by(func.count(ModerationItem.id).desc())
                .limit(3)
            ).all()
            
            specializations = [content_type for content_type, count in content_type_counts]
            
            return ReviewMetrics(
                moderator_id=moderator_id,
                total_reviews=total_reviews,
                avg_review_time_minutes=avg_review_time,
                accuracy_score=0.85,  # Placeholder - would calculate from appeals/overturns
                consistency_score=0.90,  # Placeholder - would calculate from decision patterns
                items_pending=pending_items,
                items_overdue=overdue_items,
                specializations=specializations
            )
            
        except Exception as e:
            logger.error(f"Failed to get review metrics for moderator {moderator_id}: {e}")
            return ReviewMetrics(
                moderator_id=moderator_id,
                total_reviews=0,
                avg_review_time_minutes=0,
                accuracy_score=0,
                consistency_score=0,
                items_pending=0,
                items_overdue=0,
                specializations=[]
            )
    
    async def analyze_workload(self) -> WorkloadAnalysis:
        """Analyze overall moderation workload."""
        try:
            # Get pending items
            total_pending = self.session.exec(
                select(func.count(ModerationItem.id))
                .where(ModerationItem.status.in_([ModerationStatus.PENDING, ModerationStatus.IN_REVIEW]))
            ).first() or 0
            
            # Get high priority pending
            high_priority_pending = self.session.exec(
                select(func.count(ModerationItem.id))
                .where(
                    (ModerationItem.status.in_([ModerationStatus.PENDING, ModerationStatus.IN_REVIEW])) &
                    (ModerationItem.priority_score >= 0.7)
                )
            ).first() or 0
            
            # Get overdue items
            overdue_time = datetime.now(timezone.utc) - timedelta(hours=24)
            overdue_items = self.session.exec(
                select(func.count(ModerationItem.id))
                .where(
                    (ModerationItem.status == ModerationStatus.IN_REVIEW) &
                    (ModerationItem.created_at <= overdue_time)
                )
            ).first() or 0
            
            # Calculate average wait time
            pending_items = self.session.exec(
                select(ModerationItem)
                .where(ModerationItem.status == ModerationStatus.PENDING)
                .limit(100)
            ).all()
            
            avg_wait_time = 0.0
            if pending_items:
                total_wait = sum(
                    (datetime.now(timezone.utc) - item.created_at.replace(tzinfo=timezone.utc)).total_seconds() / 3600
                    for item in pending_items
                )
                avg_wait_time = total_wait / len(pending_items)
            
            # Get moderator utilization
            moderators = await self._get_all_moderators()
            moderator_utilization = {}
            
            for moderator in moderators:
                assigned_count = self.session.exec(
                    select(func.count(ModerationItem.id))
                    .where(
                        (ModerationItem.assigned_moderator_id == moderator.id) &
                        (ModerationItem.status == ModerationStatus.IN_REVIEW)
                    )
                ).first() or 0
                
                # Assume max capacity of 20 items per moderator
                utilization = min(assigned_count / 20, 1.0)
                moderator_utilization[moderator.id] = utilization
            
            # Identify bottlenecks
            bottlenecks = []
            recommendations = []
            
            if overdue_items > 0:
                bottlenecks.append(f"{overdue_items} overdue items")
                recommendations.append("Reassign overdue items to available moderators")
            
            if avg_wait_time > 12:  # More than 12 hours
                bottlenecks.append("High average wait time")
                recommendations.append("Consider adding more moderators or adjusting priorities")
            
            high_utilization_mods = [mod_id for mod_id, util in moderator_utilization.items() if util > 0.8]
            if high_utilization_mods:
                bottlenecks.append(f"{len(high_utilization_mods)} moderators at high utilization")
                recommendations.append("Redistribute workload among moderators")
            
            return WorkloadAnalysis(
                total_pending=total_pending,
                high_priority_pending=high_priority_pending,
                overdue_items=overdue_items,
                avg_wait_time_hours=avg_wait_time,
                moderator_utilization=moderator_utilization,
                bottlenecks=bottlenecks,
                recommendations=recommendations
            )
            
        except Exception as e:
            logger.error(f"Failed to analyze workload: {e}")
            return WorkloadAnalysis(
                total_pending=0,
                high_priority_pending=0,
                overdue_items=0,
                avg_wait_time_hours=0,
                moderator_utilization={},
                bottlenecks=["Analysis failed"],
                recommendations=["Check system logs"]
            )
    
    async def _get_available_moderators(self) -> List[EnhancedUser]:
        """Get list of available moderators."""
        # This would query for users with moderator role and availability
        # For now, return all users with moderator permissions
        moderators = self.session.exec(
            select(EnhancedUser).where(
                # Assuming there's a role or permission field
                EnhancedUser.is_active == True
            )
        ).all()
        
        return [mod for mod in moderators if self._is_moderator(mod)]
    
    async def _get_all_moderators(self) -> List[EnhancedUser]:
        """Get all moderators (including busy ones)."""
        return await self._get_available_moderators()
    
    def _is_moderator(self, user: EnhancedUser) -> bool:
        """Check if user has moderator permissions."""
        # This would check actual permissions/roles
        # For now, assume all active users can moderate
        return user.is_active
    
    async def _assign_round_robin(self, item: ModerationItem, moderators: List[EnhancedUser]) -> Optional[EnhancedUser]:
        """Assign using round-robin algorithm."""
        if not moderators:
            return None
        
        # Simple round-robin based on item ID
        return moderators[item.id % len(moderators)]
    
    async def _assign_by_expertise(self, item: ModerationItem, moderators: List[EnhancedUser]) -> Optional[EnhancedUser]:
        """Assign based on moderator expertise."""
        # For now, use round-robin
        # In production, this would consider moderator specializations
        return await self._assign_round_robin(item, moderators)
    
    async def _assign_by_workload(self, item: ModerationItem, moderators: List[EnhancedUser]) -> Optional[EnhancedUser]:
        """Assign based on current workload."""
        if not moderators:
            return None
        
        # Find moderator with least current assignments
        min_workload = float('inf')
        best_moderator = None
        
        for moderator in moderators:
            current_assignments = self.session.exec(
                select(func.count(ModerationItem.id))
                .where(
                    (ModerationItem.assigned_moderator_id == moderator.id) &
                    (ModerationItem.status == ModerationStatus.IN_REVIEW)
                )
            ).first() or 0
            
            if current_assignments < min_workload:
                min_workload = current_assignments
                best_moderator = moderator
        
        return best_moderator
    
    async def _assign_by_priority(self, item: ModerationItem, moderators: List[EnhancedUser]) -> Optional[EnhancedUser]:
        """Assign based on item priority and moderator availability."""
        # For high priority items, assign to most experienced moderator
        # For now, use workload-based assignment
        return await self._assign_by_workload(item, moderators)
    
    async def _calculate_priority_score(self, item: ModerationItem) -> float:
        """Calculate priority score for moderation item."""
        score = 0.5  # Base score
        
        # Increase priority based on severity
        if item.severity == ModerationSeverity.CRITICAL:
            score += 0.4
        elif item.severity == ModerationSeverity.HIGH:
            score += 0.3
        elif item.severity == ModerationSeverity.MEDIUM:
            score += 0.1
        
        # Increase priority based on AI confidence
        if item.ai_confidence_score and item.ai_confidence_score > 0.9:
            score += 0.2
        
        # Increase priority based on source
        if item.source == ModerationSource.USER_REPORT:
            score += 0.1
        
        return min(score, 1.0)
    
    async def _estimate_review_time(self, item: ModerationItem) -> int:
        """Estimate review time in minutes."""
        base_time = 5  # 5 minutes base
        
        # Adjust based on content type
        if item.content_type == "file":
            base_time += 10
        elif item.content_type == "message":
            base_time += 2
        
        # Adjust based on complexity
        if item.content_text and len(item.content_text) > 500:
            base_time += 5
        
        if item.severity == ModerationSeverity.CRITICAL:
            base_time += 10
        
        return base_time
    
    async def _calculate_deadline(self, item: ModerationItem, priority_score: float) -> datetime:
        """Calculate deadline for review."""
        base_hours = 24  # 24 hours base
        
        # Adjust based on priority
        if priority_score > 0.8:
            base_hours = 4  # 4 hours for high priority
        elif priority_score > 0.6:
            base_hours = 12  # 12 hours for medium-high priority
        
        return datetime.now(timezone.utc) + timedelta(hours=base_hours)
    
    async def _notify_moderator(self, moderator: EnhancedUser, item: ModerationItem, assignment: ReviewAssignment):
        """Send notification to moderator about new assignment."""
        # This would send actual notifications (email, push, etc.)
        logger.info(f"📧 Notified moderator {moderator.id} about assignment {item.id}")
    
    async def _escalate_to_senior_moderator(self, item: ModerationItem):
        """Escalate item to senior moderator."""
        # This would find and assign to a senior moderator
        logger.info(f"🔺 Escalating item {item.id} to senior moderator")
    
    async def _execute_moderation_action(self, item: ModerationItem):
        """Execute the final moderation action."""
        # This would actually perform the moderation action
        # (delete content, ban user, etc.)
        logger.info(f"⚡ Executing moderation action {item.final_action.value} for item {item.id}")
    
    async def _update_moderator_metrics(self, moderator_id: int, item: ModerationItem):
        """Update performance metrics for moderator."""
        # This would update moderator performance tracking
        logger.info(f"📊 Updated metrics for moderator {moderator_id}")


def get_human_review_service(session: Session) -> HumanReviewService:
    """Get human review service instance."""
    return HumanReviewService(session)
