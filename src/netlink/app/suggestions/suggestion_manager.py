"""
Advanced Suggestions System
Comprehensive user feedback, feature requests, and improvement suggestions management.
"""

import json
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
import logging

logger = logging.getLogger("netlink.suggestions")

class SuggestionType(Enum):
    """Types of suggestions."""
    FEATURE_REQUEST = "feature_request"
    BUG_REPORT = "bug_report"
    IMPROVEMENT = "improvement"
    UI_UX = "ui_ux"
    PERFORMANCE = "performance"
    SECURITY = "security"
    DOCUMENTATION = "documentation"
    OTHER = "other"

class SuggestionStatus(Enum):
    """Suggestion status."""
    SUBMITTED = "submitted"
    UNDER_REVIEW = "under_review"
    APPROVED = "approved"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    REJECTED = "rejected"
    DUPLICATE = "duplicate"
    DEFERRED = "deferred"

class SuggestionPriority(Enum):
    """Suggestion priority levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class Suggestion:
    """Individual suggestion data structure."""
    id: str
    title: str
    description: str
    type: SuggestionType
    priority: SuggestionPriority
    status: SuggestionStatus
    submitter_id: str
    submitter_name: str
    submitter_email: str
    submitted_at: datetime
    updated_at: datetime
    assigned_to: Optional[str] = None
    estimated_effort: Optional[str] = None
    tags: List[str] = None
    votes_up: int = 0
    votes_down: int = 0
    comments: List[Dict[str, Any]] = None
    attachments: List[str] = None
    implementation_notes: str = ""
    completion_date: Optional[datetime] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []
        if self.comments is None:
            self.comments = []
        if self.attachments is None:
            self.attachments = []

class SuggestionManager:
    """Advanced suggestion management system."""
    
    def __init__(self):
        self.suggestions_dir = Path("data/suggestions")
        self.suggestions_dir.mkdir(parents=True, exist_ok=True)
        
        self.suggestions_file = self.suggestions_dir / "suggestions.json"
        self.votes_file = self.suggestions_dir / "votes.json"
        self.analytics_file = self.suggestions_dir / "analytics.json"
        
        # In-memory storage
        self.suggestions: Dict[str, Suggestion] = {}
        self.votes: Dict[str, Dict[str, str]] = {}  # user_id -> suggestion_id -> vote_type
        self.analytics = {
            "total_suggestions": 0,
            "suggestions_by_type": {},
            "suggestions_by_status": {},
            "monthly_submissions": {},
            "top_contributors": {},
            "average_resolution_time": 0
        }
        
        # Load existing data
        self.load_suggestions()
        self.load_votes()
        self.load_analytics()
        
        # Auto-categorization keywords
        self.categorization_keywords = {
            SuggestionType.FEATURE_REQUEST: [
                "feature", "add", "new", "implement", "create", "build", "develop"
            ],
            SuggestionType.BUG_REPORT: [
                "bug", "error", "issue", "problem", "broken", "crash", "fail"
            ],
            SuggestionType.IMPROVEMENT: [
                "improve", "enhance", "better", "optimize", "upgrade", "refactor"
            ],
            SuggestionType.UI_UX: [
                "ui", "ux", "interface", "design", "layout", "usability", "user experience"
            ],
            SuggestionType.PERFORMANCE: [
                "slow", "fast", "performance", "speed", "optimize", "lag", "memory"
            ],
            SuggestionType.SECURITY: [
                "security", "secure", "vulnerability", "auth", "permission", "encrypt"
            ],
            SuggestionType.DOCUMENTATION: [
                "documentation", "docs", "help", "guide", "tutorial", "manual"
            ]
        }
    
    def submit_suggestion(self, title: str, description: str, submitter_id: str,
                         submitter_name: str, submitter_email: str,
                         suggestion_type: Optional[str] = None,
                         priority: Optional[str] = None,
                         tags: Optional[List[str]] = None) -> str:
        """Submit a new suggestion."""
        try:
            # Generate unique ID
            suggestion_id = str(uuid.uuid4())
            
            # Auto-categorize if type not provided
            if not suggestion_type:
                suggestion_type = self._auto_categorize(title + " " + description)
            
            # Set default priority
            if not priority:
                priority = SuggestionPriority.MEDIUM.value
            
            # Create suggestion
            suggestion = Suggestion(
                id=suggestion_id,
                title=title.strip(),
                description=description.strip(),
                type=SuggestionType(suggestion_type),
                priority=SuggestionPriority(priority),
                status=SuggestionStatus.SUBMITTED,
                submitter_id=submitter_id,
                submitter_name=submitter_name,
                submitter_email=submitter_email,
                submitted_at=datetime.now(),
                updated_at=datetime.now(),
                tags=tags or []
            )
            
            # Store suggestion
            self.suggestions[suggestion_id] = suggestion
            self.save_suggestions()
            
            # Update analytics
            self._update_analytics_on_submission(suggestion)
            
            logger.info(f"New suggestion submitted: {suggestion_id} by {submitter_name}")
            return suggestion_id
            
        except Exception as e:
            logger.error(f"Error submitting suggestion: {e}")
            raise
    
    def get_suggestion(self, suggestion_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific suggestion."""
        if suggestion_id in self.suggestions:
            suggestion = self.suggestions[suggestion_id]
            return self._suggestion_to_dict(suggestion)
        return None
    
    def get_suggestions(self, filters: Optional[Dict[str, Any]] = None,
                       sort_by: str = "submitted_at", sort_order: str = "desc",
                       limit: Optional[int] = None, offset: int = 0) -> Dict[str, Any]:
        """Get suggestions with filtering and pagination."""
        try:
            # Apply filters
            filtered_suggestions = list(self.suggestions.values())
            
            if filters:
                filtered_suggestions = self._apply_filters(filtered_suggestions, filters)
            
            # Sort suggestions
            reverse = sort_order.lower() == "desc"
            if sort_by == "votes":
                filtered_suggestions.sort(
                    key=lambda s: s.votes_up - s.votes_down, reverse=reverse
                )
            elif sort_by == "priority":
                priority_order = {
                    SuggestionPriority.CRITICAL: 4,
                    SuggestionPriority.HIGH: 3,
                    SuggestionPriority.MEDIUM: 2,
                    SuggestionPriority.LOW: 1
                }
                filtered_suggestions.sort(
                    key=lambda s: priority_order.get(s.priority, 0), reverse=reverse
                )
            else:
                # Default to date-based sorting
                filtered_suggestions.sort(
                    key=lambda s: getattr(s, sort_by, s.submitted_at), reverse=reverse
                )
            
            # Apply pagination
            total_count = len(filtered_suggestions)
            if limit:
                end_index = offset + limit
                filtered_suggestions = filtered_suggestions[offset:end_index]
            else:
                filtered_suggestions = filtered_suggestions[offset:]
            
            # Convert to dict format
            suggestions_data = [
                self._suggestion_to_dict(suggestion) 
                for suggestion in filtered_suggestions
            ]
            
            return {
                "suggestions": suggestions_data,
                "total_count": total_count,
                "offset": offset,
                "limit": limit
            }
            
        except Exception as e:
            logger.error(f"Error getting suggestions: {e}")
            return {"suggestions": [], "total_count": 0, "offset": 0, "limit": 0}
    
    def update_suggestion_status(self, suggestion_id: str, new_status: str,
                               assigned_to: Optional[str] = None,
                               implementation_notes: str = "",
                               admin_user: str = "System") -> bool:
        """Update suggestion status."""
        try:
            if suggestion_id not in self.suggestions:
                return False
            
            suggestion = self.suggestions[suggestion_id]
            old_status = suggestion.status
            
            suggestion.status = SuggestionStatus(new_status)
            suggestion.updated_at = datetime.now()
            
            if assigned_to:
                suggestion.assigned_to = assigned_to
            
            if implementation_notes:
                suggestion.implementation_notes = implementation_notes
            
            if new_status == SuggestionStatus.COMPLETED.value:
                suggestion.completion_date = datetime.now()
            
            # Add status change comment
            self.add_comment(
                suggestion_id,
                f"Status changed from {old_status.value} to {new_status}",
                admin_user,
                is_admin=True
            )
            
            self.save_suggestions()
            self._update_analytics_on_status_change(suggestion, old_status)
            
            logger.info(f"Suggestion {suggestion_id} status updated to {new_status}")
            return True
            
        except Exception as e:
            logger.error(f"Error updating suggestion status: {e}")
            return False
    
    def vote_suggestion(self, suggestion_id: str, user_id: str, vote_type: str) -> bool:
        """Vote on a suggestion (up/down)."""
        try:
            if suggestion_id not in self.suggestions:
                return False
            
            if vote_type not in ["up", "down", "remove"]:
                return False
            
            suggestion = self.suggestions[suggestion_id]
            
            # Initialize user votes if needed
            if user_id not in self.votes:
                self.votes[user_id] = {}
            
            # Get previous vote
            previous_vote = self.votes[user_id].get(suggestion_id)
            
            # Update vote counts
            if previous_vote == "up":
                suggestion.votes_up -= 1
            elif previous_vote == "down":
                suggestion.votes_down -= 1
            
            # Apply new vote
            if vote_type == "remove":
                self.votes[user_id].pop(suggestion_id, None)
            else:
                self.votes[user_id][suggestion_id] = vote_type
                if vote_type == "up":
                    suggestion.votes_up += 1
                elif vote_type == "down":
                    suggestion.votes_down += 1
            
            suggestion.updated_at = datetime.now()
            
            self.save_suggestions()
            self.save_votes()
            
            return True
            
        except Exception as e:
            logger.error(f"Error voting on suggestion: {e}")
            return False
    
    def add_comment(self, suggestion_id: str, comment_text: str, user_name: str,
                   user_id: str = "", is_admin: bool = False) -> bool:
        """Add a comment to a suggestion."""
        try:
            if suggestion_id not in self.suggestions:
                return False
            
            suggestion = self.suggestions[suggestion_id]
            
            comment = {
                "id": str(uuid.uuid4()),
                "text": comment_text.strip(),
                "author": user_name,
                "author_id": user_id,
                "is_admin": is_admin,
                "timestamp": datetime.now().isoformat(),
                "edited": False
            }
            
            suggestion.comments.append(comment)
            suggestion.updated_at = datetime.now()
            
            self.save_suggestions()
            
            logger.info(f"Comment added to suggestion {suggestion_id} by {user_name}")
            return True
            
        except Exception as e:
            logger.error(f"Error adding comment: {e}")
            return False
    
    def get_analytics(self) -> Dict[str, Any]:
        """Get suggestion analytics and statistics."""
        self._refresh_analytics()
        return self.analytics.copy()
    
    def _auto_categorize(self, text: str) -> str:
        """Auto-categorize suggestion based on content."""
        text_lower = text.lower()
        
        scores = {}
        for suggestion_type, keywords in self.categorization_keywords.items():
            score = sum(1 for keyword in keywords if keyword in text_lower)
            if score > 0:
                scores[suggestion_type] = score
        
        if scores:
            return max(scores, key=scores.get).value
        
        return SuggestionType.OTHER.value
    
    def _apply_filters(self, suggestions: List[Suggestion], filters: Dict[str, Any]) -> List[Suggestion]:
        """Apply filters to suggestions list."""
        filtered = suggestions
        
        if "type" in filters:
            filtered = [s for s in filtered if s.type.value == filters["type"]]
        
        if "status" in filters:
            filtered = [s for s in filtered if s.status.value == filters["status"]]
        
        if "priority" in filters:
            filtered = [s for s in filtered if s.priority.value == filters["priority"]]
        
        if "submitter_id" in filters:
            filtered = [s for s in filtered if s.submitter_id == filters["submitter_id"]]
        
        if "assigned_to" in filters:
            filtered = [s for s in filtered if s.assigned_to == filters["assigned_to"]]
        
        if "tags" in filters:
            filter_tags = filters["tags"] if isinstance(filters["tags"], list) else [filters["tags"]]
            filtered = [s for s in filtered if any(tag in s.tags for tag in filter_tags)]
        
        if "search" in filters:
            search_term = filters["search"].lower()
            filtered = [
                s for s in filtered 
                if search_term in s.title.lower() or search_term in s.description.lower()
            ]
        
        if "date_from" in filters:
            date_from = datetime.fromisoformat(filters["date_from"])
            filtered = [s for s in filtered if s.submitted_at >= date_from]
        
        if "date_to" in filters:
            date_to = datetime.fromisoformat(filters["date_to"])
            filtered = [s for s in filtered if s.submitted_at <= date_to]
        
        return filtered
    
    def _suggestion_to_dict(self, suggestion: Suggestion) -> Dict[str, Any]:
        """Convert suggestion to dictionary format."""
        data = asdict(suggestion)
        
        # Convert enums to strings
        data["type"] = suggestion.type.value
        data["priority"] = suggestion.priority.value
        data["status"] = suggestion.status.value
        
        # Convert datetime objects
        data["submitted_at"] = suggestion.submitted_at.isoformat()
        data["updated_at"] = suggestion.updated_at.isoformat()
        
        if suggestion.completion_date:
            data["completion_date"] = suggestion.completion_date.isoformat()
        
        # Calculate vote score
        data["vote_score"] = suggestion.votes_up - suggestion.votes_down
        
        return data
    
    def _update_analytics_on_submission(self, suggestion: Suggestion):
        """Update analytics when a new suggestion is submitted."""
        self.analytics["total_suggestions"] += 1
        
        # Update by type
        type_key = suggestion.type.value
        if type_key not in self.analytics["suggestions_by_type"]:
            self.analytics["suggestions_by_type"][type_key] = 0
        self.analytics["suggestions_by_type"][type_key] += 1
        
        # Update by status
        status_key = suggestion.status.value
        if status_key not in self.analytics["suggestions_by_status"]:
            self.analytics["suggestions_by_status"][status_key] = 0
        self.analytics["suggestions_by_status"][status_key] += 1
        
        # Update monthly submissions
        month_key = suggestion.submitted_at.strftime("%Y-%m")
        if month_key not in self.analytics["monthly_submissions"]:
            self.analytics["monthly_submissions"][month_key] = 0
        self.analytics["monthly_submissions"][month_key] += 1
        
        # Update top contributors
        if suggestion.submitter_name not in self.analytics["top_contributors"]:
            self.analytics["top_contributors"][suggestion.submitter_name] = 0
        self.analytics["top_contributors"][suggestion.submitter_name] += 1
        
        self.save_analytics()
    
    def _update_analytics_on_status_change(self, suggestion: Suggestion, old_status: SuggestionStatus):
        """Update analytics when suggestion status changes."""
        # Update status counts
        old_status_key = old_status.value
        new_status_key = suggestion.status.value
        
        if old_status_key in self.analytics["suggestions_by_status"]:
            self.analytics["suggestions_by_status"][old_status_key] -= 1
        
        if new_status_key not in self.analytics["suggestions_by_status"]:
            self.analytics["suggestions_by_status"][new_status_key] = 0
        self.analytics["suggestions_by_status"][new_status_key] += 1
        
        self.save_analytics()
    
    def _refresh_analytics(self):
        """Refresh analytics calculations."""
        # Calculate average resolution time
        completed_suggestions = [
            s for s in self.suggestions.values() 
            if s.status == SuggestionStatus.COMPLETED and s.completion_date
        ]
        
        if completed_suggestions:
            total_time = sum(
                (s.completion_date - s.submitted_at).total_seconds()
                for s in completed_suggestions
            )
            avg_time_seconds = total_time / len(completed_suggestions)
            self.analytics["average_resolution_time"] = avg_time_seconds / 86400  # Convert to days
        
        self.save_analytics()
    
    def load_suggestions(self):
        """Load suggestions from storage."""
        if self.suggestions_file.exists():
            try:
                with open(self.suggestions_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    
                for suggestion_data in data:
                    suggestion = Suggestion(
                        id=suggestion_data["id"],
                        title=suggestion_data["title"],
                        description=suggestion_data["description"],
                        type=SuggestionType(suggestion_data["type"]),
                        priority=SuggestionPriority(suggestion_data["priority"]),
                        status=SuggestionStatus(suggestion_data["status"]),
                        submitter_id=suggestion_data["submitter_id"],
                        submitter_name=suggestion_data["submitter_name"],
                        submitter_email=suggestion_data["submitter_email"],
                        submitted_at=datetime.fromisoformat(suggestion_data["submitted_at"]),
                        updated_at=datetime.fromisoformat(suggestion_data["updated_at"]),
                        assigned_to=suggestion_data.get("assigned_to"),
                        estimated_effort=suggestion_data.get("estimated_effort"),
                        tags=suggestion_data.get("tags", []),
                        votes_up=suggestion_data.get("votes_up", 0),
                        votes_down=suggestion_data.get("votes_down", 0),
                        comments=suggestion_data.get("comments", []),
                        attachments=suggestion_data.get("attachments", []),
                        implementation_notes=suggestion_data.get("implementation_notes", ""),
                        completion_date=datetime.fromisoformat(suggestion_data["completion_date"]) 
                                      if suggestion_data.get("completion_date") else None
                    )
                    
                    self.suggestions[suggestion.id] = suggestion
                    
            except Exception as e:
                logger.error(f"Error loading suggestions: {e}")
    
    def save_suggestions(self):
        """Save suggestions to storage."""
        try:
            suggestions_data = [
                self._suggestion_to_dict(suggestion)
                for suggestion in self.suggestions.values()
            ]
            
            with open(self.suggestions_file, 'w', encoding='utf-8') as f:
                json.dump(suggestions_data, f, indent=2, ensure_ascii=False)
                
        except Exception as e:
            logger.error(f"Error saving suggestions: {e}")
    
    def load_votes(self):
        """Load votes from storage."""
        if self.votes_file.exists():
            try:
                with open(self.votes_file, 'r', encoding='utf-8') as f:
                    self.votes = json.load(f)
            except Exception as e:
                logger.error(f"Error loading votes: {e}")
    
    def save_votes(self):
        """Save votes to storage."""
        try:
            with open(self.votes_file, 'w', encoding='utf-8') as f:
                json.dump(self.votes, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving votes: {e}")
    
    def load_analytics(self):
        """Load analytics from storage."""
        if self.analytics_file.exists():
            try:
                with open(self.analytics_file, 'r', encoding='utf-8') as f:
                    saved_analytics = json.load(f)
                    self.analytics.update(saved_analytics)
            except Exception as e:
                logger.error(f"Error loading analytics: {e}")
    
    def save_analytics(self):
        """Save analytics to storage."""
        try:
            with open(self.analytics_file, 'w', encoding='utf-8') as f:
                json.dump(self.analytics, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving analytics: {e}")

# Global suggestion manager instance
suggestion_manager = SuggestionManager()
