"""Gerçek HTTP istekleri atan entegrasyon testleri için ortak fixture'lar.

`search_history` tablosu Postgres'e özgü `JSONB` kolonu kullandığı için
(bkz. app/models/search_history.py) SQLite in-memory ile test edilemiyor
(SQLAlchemy DDL derlemesi patlıyor, ayrıca aiosqlite bağımlılığı da yok).
Bunun yerine aynı Postgres sunucusunda (docker-compose'daki `postgres`
container'ı) ayrı bir `aegis_cti_test` veritabanı kullanılır — geliştirme
verisine hiç dokunulmaz.

Her test kendi transaction'ında (SAVEPOINT ile iç içe) çalışır ve test
sonunda rollback edilir; endpoint kodunun kendi içinde attığı `commit()`
çağrıları (örn. bookmarks.py) dış transaction'ı sonlandırmaz.
"""

import asyncio
from collections.abc import AsyncIterator

import asyncpg
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings
from app.db.base import Base
from app.db.session import get_db_session
from app.main import create_application
from app.services.auth import create_access_token
from app.services.rate_limiter import _client as _redis_client

TEST_DB_NAME = f"{settings.POSTGRES_DB}_test"


def _admin_dsn() -> str:
    return (
        f"postgresql://{settings.POSTGRES_USER}:{settings.POSTGRES_PASSWORD}"
        f"@{settings.POSTGRES_HOST}:{settings.POSTGRES_PORT}/{settings.POSTGRES_DB}"
    )


def _test_dsn() -> str:
    return (
        f"postgresql+asyncpg://{settings.POSTGRES_USER}:{settings.POSTGRES_PASSWORD}"
        f"@{settings.POSTGRES_HOST}:{settings.POSTGRES_PORT}/{TEST_DB_NAME}"
    )


async def _prepare_test_database() -> None:
    admin_conn = await asyncpg.connect(dsn=_admin_dsn())
    try:
        exists = await admin_conn.fetchval(
            "SELECT 1 FROM pg_database WHERE datname = $1", TEST_DB_NAME
        )
        if not exists:
            await admin_conn.execute(f'CREATE DATABASE "{TEST_DB_NAME}"')
    finally:
        await admin_conn.close()

    engine = create_async_engine(_test_dsn(), future=True)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)
    finally:
        await engine.dispose()


@pytest.fixture(scope="session", autouse=True)
def _test_database() -> None:
    """Test DB'sini bir kez, kendi (pytest-asyncio'dan bağımsız) event loop'unda hazırlar.

    Bilinçli olarak `pytest_asyncio.fixture` DEĞİL: session scope'lu bir async
    fixture, pytest.ini'deki `asyncio_default_fixture_loop_scope = function`
    ile çakışıp (ScopeMismatch) her test fonksiyonunun kendi event loop'una
    bağlı olan asyncpg bağlantılarıyla karışır. `asyncio.run` burada tamamen
    ayrı, kısa ömürlü bir loop kullanır.
    """
    asyncio.run(_prepare_test_database())


@pytest_asyncio.fixture
async def db_session() -> AsyncIterator[AsyncSession]:
    engine = create_async_engine(_test_dsn(), future=True)
    connection: AsyncConnection = await engine.connect()
    outer_transaction = await connection.begin()

    session_factory = async_sessionmaker(
        bind=connection,
        class_=AsyncSession,
        expire_on_commit=False,
        join_transaction_mode="create_savepoint",
    )
    session = session_factory()

    try:
        yield session
    finally:
        await session.close()
        await outer_transaction.rollback()
        await connection.close()
        await engine.dispose()


@pytest_asyncio.fixture
async def app(db_session: AsyncSession):
    application = create_application()

    async def _get_db_override() -> AsyncIterator[AsyncSession]:
        yield db_session

    application.dependency_overrides[get_db_session] = _get_db_override
    yield application
    application.dependency_overrides.clear()


@pytest_asyncio.fixture
async def client(app) -> AsyncIterator[AsyncClient]:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture
def admin_headers() -> dict[str, str]:
    token = create_access_token(settings.ADMIN_USERNAME)
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture(autouse=True)
async def _reset_redis_connection_pool() -> AsyncIterator[None]:
    """rate_limiter.py'deki modül seviyeli Redis client'ı, her testin kendi
    (pytest-asyncio'nun her test fonksiyonu için ayrı açtığı) event loop'una
    bağlı bağlantılarla kirlenmesin diye her testten sonra havuzu boşaltır.

    Aksi halde bir sonraki test yeni bir loop'ta çalışırken önceki loop'a
    bağlı, artık kapanmış bir bağlantı kullanılmaya çalışılır ve
    "attached to a different loop" hatası alınır.
    """
    yield
    await _redis_client.connection_pool.disconnect()
