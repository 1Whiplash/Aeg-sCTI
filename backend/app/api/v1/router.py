"""v1 API için ana router agregasyonu."""

from fastapi import APIRouter

from app.api.v1 import actions, auth, health, history, ioc, whitelist

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(ioc.router)
api_router.include_router(history.router)
api_router.include_router(actions.router)
api_router.include_router(whitelist.router)
