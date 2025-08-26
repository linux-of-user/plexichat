import random
from typing import Dict, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/easter-eggs", tags=["Easter Eggs"])

class BrewRequest(BaseModel):
    beverage: str

@router.get("/")
async def easter_egg_index():
    """Lists available Easter eggs."""
    return {
        "message": "Welcome to PlexiChat Easter Eggs!",
        "eggs": ["/fortune", "/brew", "/dad-joke"]
    }

@router.get("/fortune")
async def get_fortune():
    """Returns a random fortune cookie."""
    fortunes = [
        "Your code will compile on the first try.",
        "A bug you've been hunting will reveal itself.",
        "The documentation you need exists.",
    ]
    return {"fortune": random.choice(fortunes)}

@router.post("/brew")
async def brew_beverage(req: BrewRequest):
    """Attempts to brew a beverage."""
    if req.beverage.lower() == "coffee":
        raise HTTPException(status_code=418, detail="I'm a teapot")
    return {"message": f"Sorry, can only brew coffee, not {req.beverage}."}

@router.get("/dad-joke")
async def get_dad_joke():
    """Returns a random dad joke."""
    jokes = [
        "Why do programmers prefer dark mode? Because light attracts bugs!",
        "How many programmers does it take to change a light bulb? None. It's a hardware problem.",
    ]
    return {"joke": random.choice(jokes)}

if __name__ == '__main__':
    # Example of how to run this API with uvicorn
    import uvicorn
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(router)

    # uvicorn.run(app, host="0.0.0.0", port=8000)
