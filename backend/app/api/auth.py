"""Authentication API endpoints for registration, login, and user profiles."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from backend.app.api.deps import get_current_active_user
from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.core.security import hash_password, verify_password, create_access_token
from backend.app.database.connection import get_db
from backend.app.models.user import User
from backend.app.schemas.auth import (
    UserRole,
    UserRegisterRequest,
    UserLoginRequest,
    UserResponse,
    TokenResponse,
)

router = APIRouter(prefix="/auth", tags=["Authentication & Access Control"])


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register New Analyst User",
    description="Creates a new user account with securely hashed credentials and default analyst role.",
)
def register_user(
    payload: UserRegisterRequest,
    db: Session = Depends(get_db),
) -> UserResponse:
    """Register a new user account. Role is strictly assigned server-side as 'analyst'."""
    # Check for existing email or username conflict
    existing_user = db.execute(
        select(User).where(
            or_(User.email == payload.email, User.username == payload.username)
        )
    ).scalar_one_or_none()

    if existing_user:
        if existing_user.email == payload.email:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A user with this email address already exists",
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A user with this username already exists",
            )

    # Securely hash password
    hashed_pw = hash_password(payload.password)

    new_user = User(
        email=payload.email,
        username=payload.username,
        hashed_password=hashed_pw,
        full_name=payload.full_name,
        role=UserRole.ANALYST.value,
        is_active=True,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    logger.info(f"User registered successfully: username='{new_user.username}', role='{new_user.role}'")
    return UserResponse.model_validate(new_user)


@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Authenticate User & Obtain JWT",
    description="Authenticates using username or email and returns a signed JWT access token.",
)
def login_user(
    payload: UserLoginRequest,
    db: Session = Depends(get_db),
) -> TokenResponse:
    """Authenticate credentials and generate JWT token."""
    user = db.execute(
        select(User).where(
            or_(
                User.username == payload.username_or_email,
                User.email == payload.username_or_email,
            )
        )
    ).scalar_one_or_none()

    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated",
        )

    # Generate access token
    token_claims = {
        "sub": str(user.id),
        "username": user.username,
        "role": user.role,
    }
    access_token = create_access_token(data=token_claims)
    expires_in_seconds = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60

    logger.info(f"User logged in successfully: username='{user.username}'")
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in_seconds=expires_in_seconds,
        user=UserResponse.model_validate(user),
    )


@router.get(
    "/me",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Current Authenticated User",
    description="Returns the profile information of the currently authenticated analyst.",
)
def get_me(
    current_user: User = Depends(get_current_active_user),
) -> UserResponse:
    """Retrieve current user profile."""
    return UserResponse.model_validate(current_user)
