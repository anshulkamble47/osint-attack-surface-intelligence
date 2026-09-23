"""Authentication request and response validation schemas."""

import uuid
from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, EmailStr, Field, ConfigDict


class UserRole(str, Enum):
    """User access roles for the platform."""
    ADMIN = "admin"
    ANALYST = "analyst"
    AUDITOR = "auditor"


class UserRegisterRequest(BaseModel):
    """Schema for user registration. Role is assigned strictly server-side."""
    email: str = Field(
        ...,
        pattern=r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$",
        description="Unique email address",
        examples=["analyst@example.com"],
    )
    username: str = Field(
        ...,
        min_length=3,
        max_length=50,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Alphanumeric username (underscores and hyphens allowed)",
        examples=["analyst_jane"],
    )
    password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="Plaintext password (minimum 8 characters)",
    )
    full_name: Optional[str] = Field(
        None, max_length=255, description="Full display name"
    )

    model_config = ConfigDict(extra="forbid")


class UserLoginRequest(BaseModel):
    """Schema for user login with either username or email."""
    username_or_email: str = Field(
        ...,
        min_length=3,
        description="Username or email address",
        examples=["analyst_jane", "jane@example.com"],
    )
    password: str = Field(
        ...,
        min_length=1,
        description="Account password",
    )


class UserResponse(BaseModel):
    """Safe user profile response schema excluding password hashes."""
    id: uuid.UUID
    email: str
    username: str
    full_name: Optional[str] = None
    role: str
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TokenResponse(BaseModel):
    """JWT authentication token response with user profile."""
    access_token: str
    token_type: str = "bearer"
    expires_in_seconds: int
    user: UserResponse
