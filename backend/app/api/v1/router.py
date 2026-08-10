"""v1 API için ana router agregasyonu."""

from fastapi import APIRouter

from app.api.v1 import health, history, ioc

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(ioc.router)
api_router.include_router(history.router)
