"""Coğrafi konum şeması (tehdit haritası için)."""

from pydantic import BaseModel


class GeoLocation(BaseModel):
    lat: float
    lon: float
    country: str | None = None
    city: str | None = None
