from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, EmailStr, Field


class UserCreate(BaseModel):
    login: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=4, max_length=256)
    email: EmailStr
    display_name: str | None = Field(default=None, max_length=255)


class UserUpdate(BaseModel):
    login: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=4, max_length=256)
    email: EmailStr
    display_name: str | None = Field(default=None, max_length=255)


class UserRead(BaseModel):
    id: int
    login: str
    email: EmailStr
    display_name: str | None
    created_at: datetime

    model_config = {"from_attributes": True}
