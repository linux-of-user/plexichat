#!/usr/bin/env python3
"""
Easter Egg API Endpoints
Fun endpoints that don't disrupt normal operation but provide entertainment
"""

import time
import random
import hashlib
from datetime import datetime
from typing import Dict, Any, Optional
from fastapi import APIRouter, HTTPException, Request, Header
from pydantic import BaseModel
import logging

# Import our enhanced error handling
try:
    from ....core.error_handling.enhanced_error_responses import check_for_teapot_condition
    from ....core.security.security_decorators import rate_limit, audit_access
except ImportError as e:
    print(f"Import error in easter eggs: {e}")
    def check_for_teapot_condition(*args, **kwargs): return False
    def rate_limit(*args, **kwargs):
        def decorator(func): return func
        return decorator
    def audit_access(*args, **kwargs):
        def decorator(func): return func
        return decorator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/easter-eggs", tags=["easter-eggs"])

class BrewRequest(BaseModel):
    """Request model for brewing beverages."""
    beverage: str
    size: str = "medium"
    temperature: str = "hot"
    special_instructions: Optional[str] = None

class FortuneResponse(BaseModel):
    """Response model for fortune cookies."""
    fortune: str
    lucky_numbers: list[int]
    timestamp: str

@router.get("/")
async def easter_egg_index():
    """List available Easter eggs."""
    return {}
        "message": "? Welcome to PlexiChat Easter Eggs! ?",
        "available_eggs": [
            {
                "endpoint": "/fortune",
                "description": "Get a random fortune cookie",
                "method": "GET"
            },
            {
                "endpoint": "/brew",
                "description": "Try to brew beverages (may surprise you!)",
                "method": "POST"
            },
            {
                "endpoint": "/magic-8-ball",
                "description": "Ask the magic 8-ball a question",
                "method": "POST"
            },
            {
                "endpoint": "/dad-joke",
                "description": "Get a random dad joke",
                "method": "GET"
            },
            {
                "endpoint": "/system-haiku",
                "description": "Get a haiku about the system status",
                "method": "GET"
            }
        ],
        "note": "These endpoints are for fun and don't affect normal PlexiChat operations",
        "secret_hint": "Try brewing coffee with special headers... ?"
    }

@router.get("/fortune", response_model=FortuneResponse)
@rate_limit(requests_per_minute=10)
async def get_fortune():
    """Get a random fortune cookie."""
    fortunes = [
        "Your code will compile on the first try today.",
        "A bug you've been hunting will reveal itself soon.",
        "Your next commit will be the one that fixes everything.",
        "The documentation you need exists and is well-written.",
        "Your tests will pass without any modifications.",
        "A senior developer will approve your pull request quickly.",
        "You will remember to save your work before the power goes out.",
        "The production deployment will go smoothly.",
        "Your code review will have only positive feedback.",
        "You will find the perfect Stack Overflow answer.",
        "Your database migration will complete without errors.",
        "The client will love your implementation.",
        "Your API will handle edge cases gracefully.",
        "You will write clean, maintainable code today.",
        "The security audit will find no vulnerabilities."
    ]
    
    fortune = random.choice(fortunes)
    lucky_numbers = sorted(random.sample(range(1, 100), 6))
    
    return FortuneResponse(
        fortune=fortune,
        lucky_numbers=lucky_numbers,
        timestamp=datetime.now().isoformat()
    )

@router.post("/brew")
@rate_limit(requests_per_minute=5)
@audit_access("brew", "beverage")
async def brew_beverage(
    request: Request,
    brew_request: BrewRequest,
    x_brew_coffee: Optional[str] = Header(None)
):
    """Attempt to brew a beverage. May have surprising results for coffee requests!"""
    
    # Check for the special teapot condition
    request_content = f"{brew_request.beverage} {brew_request.special_instructions or ''}"
    headers = dict(request.headers)
    
    # Special handling for coffee requests with the right conditions
    if (brew_request.beverage.lower() == "coffee" and 
        x_brew_coffee == "true" and 
        brew_request.special_instructions and
        "please brew coffee" in brew_request.special_instructions.lower()):
        
        # This is the Easter egg condition for 418!
        raise HTTPException(
            status_code=418,
            detail={
                "error": "I'm a teapot",
                "message": "I'm a teapot - The server refuses to brew coffee because it is, permanently, a teapot ?",
                "suggestions": [
                    "This is an Easter egg error from RFC 2324 (April 1, 1998)",
                    "Try requesting tea instead of coffee ?",
                    "The server is having a bit of fun with you!",
                    "Congratulations on finding this Easter egg!",
                    "To trigger this: POST to /brew with beverage='coffee', X-Brew-Coffee: true header, and 'please brew coffee' in special_instructions"
                ],
                "rfc": "https://tools.ietf.org/html/rfc2324",
                "easter_egg": True
            }
        )
    
    # Normal beverage brewing
    if brew_request.beverage.lower() in ["tea", "herbal tea", "green tea", "black tea"]:
        return {}
            "success": True,
            "message": f"Successfully brewed {brew_request.size} {brew_request.temperature} {brew_request.beverage} ?",
            "brewing_time": "3-5 minutes",
            "temperature": f"{brew_request.temperature} (optimal for tea)",
            "note": "Perfect choice! Tea is always a good idea."
        }
    elif brew_request.beverage.lower() == "coffee":
        return {}
            "success": False,
            "message": "Sorry, this server is a teapot and cannot brew coffee ?",
            "suggestion": "Try requesting tea instead! ?",
            "hint": "Add the X-Brew-Coffee header and special instructions for a surprise...",
            "alternative": "We can brew excellent tea though!"
        }
    else:
        return {}
            "success": False,
            "message": f"Unknown beverage: {brew_request.beverage}",
            "supported_beverages": ["tea", "herbal tea", "green tea", "black tea"],
            "note": "This server specializes in tea brewing"
        }

@router.post("/magic-8-ball")
@rate_limit(requests_per_minute=10)
async def magic_8_ball(question: Dict[str, str]):
    """Ask the magic 8-ball a question."""
    responses = [
        "It is certain",
        "Reply hazy, try again",
        "Don't count on it",
        "It is decidedly so",
        "My sources say no",
        "Without a doubt",
        "Outlook not so good",
        "Yes definitely",
        "Very doubtful",
        "You may rely on it",
        "Ask again later",
        "Concentrate and ask again",
        "Most likely",
        "Outlook good",
        "Yes",
        "Signs point to yes",
        "Better not tell you now",
        "Cannot predict now",
        "My reply is no",
        "As I see it, yes"
    ]
    
    user_question = question.get("question", "")
    if not user_question:
        raise HTTPException(status_code=400, detail="Please provide a question")
    
    # Add some randomness based on question content
    question_hash = hashlib.md5(user_question.encode()).hexdigest()
    seed = int(question_hash[:8], 16)
    random.seed(seed)
    
    response = random.choice(responses)
    
    return {}
        "question": user_question,
        "answer": response,
        "magic_8_ball": "?",
        "timestamp": datetime.now().isoformat(),
        "confidence": random.randint(1, 100)
    }

@router.get("/dad-joke")
@rate_limit(requests_per_minute=10)
async def get_dad_joke():
    """Get a random programming dad joke."""
    jokes = [
        {
            "setup": "Why do programmers prefer dark mode?",
            "punchline": "Because light attracts bugs!"
        },
        {
            "setup": "How many programmers does it take to change a light bulb?",
            "punchline": "None. That's a hardware problem."
        },
        {
            "setup": "Why do Java developers wear glasses?",
            "punchline": "Because they can't C#!"
        },
        {
            "setup": "What's a programmer's favorite hangout place?",
            "punchline": "Foo Bar!"
        },
        {
            "setup": "Why did the programmer quit his job?",
            "punchline": "He didn't get arrays!"
        },
        {
            "setup": "What do you call a programmer from Finland?",
            "punchline": "Nerdic!"
        },
        {
            "setup": "Why do programmers always mix up Halloween and Christmas?",
            "punchline": "Because Oct 31 equals Dec 25!"
        },
        {
            "setup": "What's the object-oriented way to become wealthy?",
            "punchline": "Inheritance!"
        },
        {
            "setup": "Why did the developer go broke?",
            "punchline": "Because he used up all his cache!"
        },
        {
            "setup": "What do you call a programmer who doesn't comment their code?",
            "punchline": "A mystery writer!"
        }
    ]
    
    joke = random.choice(jokes)
    
    return {}
        "setup": joke["setup"],
        "punchline": joke["punchline"],
        "type": "dad_joke",
        "rating": "groan-worthy",
        "timestamp": datetime.now().isoformat()
    }

@router.get("/system-haiku")
@rate_limit(requests_per_minute=5)
async def get_system_haiku():
    """Get a haiku about the current system status."""
    haikus = [
        {
            "lines": [
                "Servers humming soft",
                "Data flows like gentle streams",
                "PlexiChat runs well"
            ]
        },
        {
            "lines": [
                "Code compiles cleanly",
                "Tests pass with green checkmarks bright",
                "Deployment succeeds"
            ]
        },
        {
            "lines": [
                "Logs scroll endlessly",
                "Each line tells a story true",
                "System health is good"
            ]
        },
        {
            "lines": [
                "Users chat with joy",
                "Messages flow back and forth",
                "Connection is strong"
            ]
        },
        {
            "lines": [
                "Database queries",
                "Return results lightning fast",
                "Performance shines bright"
            ]
        }
    ]
    
    haiku = random.choice(haikus)
    
    return {}
        "haiku": haiku["lines"],
        "theme": "system_status",
        "style": "traditional_5_7_5",
        "timestamp": datetime.now().isoformat(),
        "zen_level": "maximum"
    }

@router.get("/konami")
async def konami_code():
    """Secret Konami code endpoint."""
    return {}
        "message": "[GAME] KONAMI CODE ACTIVATED! [GAME]",
        "code": "^ ^ v v < > < > B A",
        "reward": "You found the secret developer endpoint!",
        "easter_egg": True,
        "developer_message": "Thanks for exploring PlexiChat's Easter eggs!",
        "bonus": {
            "infinite_lives": False,
            "god_mode": False,
            "all_weapons": False,
            "note": "This isn't actually a game, but we appreciate the nostalgia!"
        }
    }

# Hidden endpoint that requires specific knowledge
@router.get("/the-answer")
async def the_answer():
    """The answer to the ultimate question of life, the universe, and everything."""
    return {}
        "question": "What is the answer to the ultimate question of life, the universe, and everything?",
        "answer": 42,
        "source": "The Hitchhiker's Guide to the Galaxy",
        "author": "Douglas Adams",
        "note": "Don't panic!",
        "towel_status": "recommended",
        "babel_fish": "not included"
    }
