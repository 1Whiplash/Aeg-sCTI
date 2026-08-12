"""
AegisCTI - Merkezi Konfigürasyon Modülü
=========================================
Pydantic BaseSettings kullanılarak tüm ortam değişkenleri (API Key'ler,
veritabanı bağlantıları, servis URL'leri vb.) tip güvenli ve tek noktadan
yönetilir. SOLID prensiplerinden "Single Responsibility" gereği bu modül
sadece konfigürasyon okuma/doğrulama sorumluluğunu taşır.
"""

from functools import lru_cache
from typing import List, Literal

from pydantic import AnyHttpUrl, Field, PostgresDsn, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Uygulama genelinde kullanılan tüm ayarlar."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Genel Uygulama Ayarları ---
    APP_NAME: str = "AegisCTI"
    APP_VERSION: str = "0.1.0"
    ENVIRONMENT: Literal["development", "staging", "production"] = "development"
    DEBUG: bool = True
    API_V1_PREFIX: str = "/api/v1"

    # Faz 1: Sistem salt-okunur (Read-Only) modda çalışır.
    # SOAR aksiyon modülleri (otomatik müdahale) bu bayrak False iken devre dışıdır.
    READ_ONLY_MODE: bool = True

    # --- Güvenlik ---
    SECRET_KEY: str = Field(default="CHANGE_ME_IN_PRODUCTION", min_length=8)
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24
    # Whitelist yazma ve FortiGate aksiyonu gibi durum değiştiren uçlar bu
    # kullanıcı adı/şifre ile korunur (analyze/history gibi salt-okunur uçlar
    # Faz 1 felsefesiyle uyumlu şekilde açık kalır).
    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str = Field(default="CHANGE_ME_IN_PRODUCTION", min_length=6)

    # --- CORS ---
    BACKEND_CORS_ORIGINS: List[AnyHttpUrl] = []

    @field_validator("BACKEND_CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: str | List[str]) -> List[str] | str:
        if isinstance(v, str) and not v.startswith("["):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v

    # --- PostgreSQL ---
    POSTGRES_HOST: str = "postgres"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = "aegis"
    POSTGRES_PASSWORD: str = "aegis_password"
    POSTGRES_DB: str = "aegis_cti"

    @property
    def SQLALCHEMY_DATABASE_URI(self) -> str:
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    # --- Redis (Cache / Task Queue) ---
    REDIS_HOST: str = "redis"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0

    @property
    def REDIS_URL(self) -> str:
        return f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"

    # Aynı IOC'nin bu süre içinde tekrar sorgulanması önbellekten karşılanır.
    CACHE_TTL_SECONDS: int = 1200  # 20 dakika

    # --- Ollama / LLM (Qwen 2.5) ---
    OLLAMA_BASE_URL: str = "http://ollama:11434"
    OLLAMA_MODEL: str = "qwen2.5:7b"
    OLLAMA_REQUEST_TIMEOUT: int = 120

    # --- Tehdit İstihbaratı Kaynak API Key'leri ---
    VIRUSTOTAL_API_KEY: str | None = None
    SHODAN_API_KEY: str | None = None
    ABUSEIPDB_API_KEY: str | None = None
    OTX_API_KEY: str | None = None  # AlienVault Open Threat Exchange
    MISP_URL: str | None = None
    MISP_API_KEY: str | None = None

    # --- FortiGate SOAR (Faz 1: Pasif/Standby) ---
    FORTIGATE_HOST: str | None = None
    FORTIGATE_API_KEY: str | None = None
    FORTIGATE_VERIFY_SSL: bool = True
    # Bu bayrak açık olmadan fortigate_service hiçbir isteği dışarı göndermez.
    FORTIGATE_AUTO_BLOCK_ENABLED: bool = False

    # --- Loglama ---
    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    # --- Ters Proxy ---
    # Açıksa rate limiter istemci IP'sini X-Forwarded-For başlığından okur.
    # SADECE gerçek, güvenilir bir ters proxy (nginx, Vite proxy vb.) bu
    # başlığı kendisi ekleyip üzerine yazıyorsa açılmalı — aksi halde istemci
    # başlığı serbestçe sahteleyip rate limiti tamamen atlatabilir.
    TRUST_PROXY_HEADERS: bool = False


@lru_cache
def get_settings() -> Settings:
    """Settings nesnesini önbelleğe alarak tekrar tekrar .env okumasını önler."""
    return Settings()


settings = get_settings()
