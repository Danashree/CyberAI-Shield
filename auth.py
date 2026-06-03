"""
Auth — JWT + SQLite persistent users + RBAC
"""

from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy import select
import uuid
import os

from database import AsyncSessionLocal, UserModel

router = APIRouter()

pwd_context   = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

SECRET_KEY = os.getenv("SECRET_KEY", "fallback-secret")
ALGORITHM  = os.getenv("ALGORITHM", "HS256")
EXPIRE_MIN = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 60))


# ── Schemas ───────────────────────────────────────────────────
class Token(BaseModel):
    access_token: str
    token_type:   str
    role:         str
    name:         str
    email:        str
    avatar:       str

class TokenData(BaseModel):
    email: Optional[str] = None
    role:  Optional[str] = None

class UserOut(BaseModel):
    name:       str
    email:      str
    role:       str
    avatar:     str
    department: Optional[str] = ""

class RegisterRequest(BaseModel):
    name:       str
    email:      str
    password:   str
    role:       Optional[str] = "analyst"
    department: Optional[str] = ""

class UpdateProfileRequest(BaseModel):
    name:       Optional[str] = None
    avatar:     Optional[str] = None
    department: Optional[str] = None


# ── Helpers ───────────────────────────────────────────────────
def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire    = datetime.utcnow() + timedelta(minutes=EXPIRE_MIN)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_user_by_email(email: str) -> Optional[UserModel]:
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(UserModel).where(UserModel.email == email)
        )
        return result.scalar_one_or_none()


# ── Dependency ────────────────────────────────────────────────
async def get_current_user(token: str = Depends(oauth2_scheme)) -> UserOut:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = await get_user_by_email(email)
    if user is None or not user.is_active:
        raise credentials_exception

    return UserOut(
        name=user.name, email=user.email,
        role=user.role, avatar=user.avatar,
        department=user.department or ""
    )

async def require_analyst(current_user: UserOut = Depends(get_current_user)):
    if current_user.role not in ["analyst", "admin"]:
        raise HTTPException(403, "Analyst or Admin role required")
    return current_user

async def require_admin(current_user: UserOut = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(403, "Admin role required")
    return current_user


# ── Routes ────────────────────────────────────────────────────
@router.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await get_user_by_email(form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_pw):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )
    if not user.is_active:
        raise HTTPException(403, "Account is disabled")

    # Update last login
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(UserModel).where(UserModel.email == user.email)
        )
        db_user = result.scalar_one_or_none()
        if db_user:
            db_user.last_login = datetime.utcnow()
            await db.commit()

    token = create_access_token({
        "sub":    user.email,
        "role":   user.role,
        "name":   user.name,
        "avatar": user.avatar,
    })
    return Token(
        access_token=token,
        token_type="bearer",
        role=user.role,
        name=user.name,
        email=user.email,
        avatar=user.avatar,
    )


@router.post("/register")
async def register(req: RegisterRequest):
    # Check if email exists
    existing = await get_user_by_email(req.email)
    if existing:
        raise HTTPException(400, "Email already registered")
    if len(req.password) < 6:
        raise HTTPException(400, "Password must be at least 6 characters")
    if req.role not in ["analyst", "admin", "viewer"]:
        req.role = "analyst"

    avatar = req.name[0].upper() if req.name else "U"
    new_user = UserModel(
        id         = str(uuid.uuid4()),
        name       = req.name,
        email      = req.email,
        role       = req.role,
        avatar     = avatar,
        hashed_pw  = pwd_context.hash(req.password),
        department = req.department or "",
        is_active  = True,
    )

    async with AsyncSessionLocal() as db:
        db.add(new_user)
        await db.commit()

    token = create_access_token({
        "sub":    req.email,
        "role":   req.role,
        "name":   req.name,
        "avatar": avatar,
    })
    return {
        "message":      "Account created successfully",
        "access_token": token,
        "token_type":   "bearer",
        "role":         req.role,
        "name":         req.name,
        "email":        req.email,
        "avatar":       avatar,
    }


@router.get("/me", response_model=UserOut)
async def get_me(current_user: UserOut = Depends(get_current_user)):
    return current_user


@router.put("/profile")
async def update_profile(
    req: UpdateProfileRequest,
    current_user: UserOut = Depends(get_current_user),
):
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(UserModel).where(UserModel.email == current_user.email)
        )
        user = result.scalar_one_or_none()
        if not user:
            raise HTTPException(404, "User not found")
        if req.name:
            user.name   = req.name
            user.avatar = req.name[0].upper()
        if req.department is not None:
            user.department = req.department
        await db.commit()
        return {
            "message":    "Profile updated",
            "name":       user.name,
            "avatar":     user.avatar,
            "department": user.department,
        }


@router.get("/users")
async def list_users(current_user: UserOut = Depends(get_current_user)):
    """List all users — available to all authenticated users for settings page."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(UserModel).order_by(UserModel.created_at))
        users  = result.scalars().all()
        return [
            {
                "id":         u.id,
                "name":       u.name,
                "email":      u.email,
                "role":       u.role,
                "avatar":     u.avatar,
                "department": u.department or "",
                "is_active":  u.is_active,
                "created_at": u.created_at.isoformat() if u.created_at else "",
                "last_login": u.last_login.isoformat() if u.last_login else "Never",
            }
            for u in users
        ]


@router.put("/users/{user_id}/role")
async def change_user_role(
    user_id: str,
    role:    str,
    current_user: UserOut = Depends(require_admin),
):
    """Admin only — change a user's role."""
    if role not in ["analyst", "admin", "viewer"]:
        raise HTTPException(400, "Invalid role")
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(UserModel).where(UserModel.id == user_id)
        )
        user = result.scalar_one_or_none()
        if not user:
            raise HTTPException(404, "User not found")
        user.role = role
        await db.commit()
    return {"message": f"Role updated to {role}"}


@router.put("/users/{user_id}/toggle")
async def toggle_user_status(
    user_id: str,
    current_user: UserOut = Depends(require_admin),
):
    """Admin only — enable/disable a user."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(UserModel).where(UserModel.id == user_id)
        )
        user = result.scalar_one_or_none()
        if not user:
            raise HTTPException(404, "User not found")
        user.is_active = not user.is_active
        await db.commit()
    return {"message": f"User {'enabled' if user.is_active else 'disabled'}"}


@router.delete("/users/{user_id}")
async def delete_user(
    user_id: str,
    current_user: UserOut = Depends(require_admin),
):
    """Admin only — delete a user."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(UserModel).where(UserModel.id == user_id)
        )
        user = result.scalar_one_or_none()
        if not user:
            raise HTTPException(404, "User not found")
        await db.delete(user)
        await db.commit()
    return {"message": "User deleted"}