"""AegisCTI FastAPI uygulama giriş noktası."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.router import api_router
from app.core.config import settings
from app.core.logging_config import configure_logging
from app.services.bookmark_scheduler import create_scheduler


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    scheduler = create_scheduler()
    if scheduler is not None:
        scheduler.start()
    yield
    if scheduler is not None:
        scheduler.shutdown(wait=False)


def create_application() -> FastAPI:
    """FastAPI application factory (test edilebilirlik için)."""
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description="Otonom Siber Tehdit İstihbaratı ve SOAR Platformu — Faz 1 (Read-Only)",
        lifespan=lifespan,
    )

    if settings.BACKEND_CORS_ORIGINS:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=[str(origin) for origin in settings.BACKEND_CORS_ORIGINS],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    app.include_router(api_router, prefix=settings.API_V1_PREFIX)
    return app


app = create_application()
