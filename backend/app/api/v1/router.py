"""v1 API için ana router agregasyonu."""

from fastapi import APIRouter

from app.api.v1 import health, ioc

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(ioc.router)
