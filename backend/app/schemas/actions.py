"""SOAR aksiyon uç noktalarının istek/yanıt şemaları."""

import ipaddress

from pydantic import BaseModel, Field, field_validator


class BlockIPRequest(BaseModel):
    ip_address: str = Field(..., description="Engellenecek IP adresi")

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, value: str) -> str:
        try:
            ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("Geçerli bir IP adresi değil.") from exc
        return value


class BlockIPResponse(BaseModel):
    blocked: bool
    message: str
