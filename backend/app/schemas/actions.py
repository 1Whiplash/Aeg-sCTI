"""SOAR aksiyon uç noktalarının istek/yanıt şemaları."""

from pydantic import BaseModel, Field


class BlockIPRequest(BaseModel):
    ip_address: str = Field(..., description="Engellenecek IP adresi")


class BlockIPResponse(BaseModel):
    blocked: bool
    message: str
