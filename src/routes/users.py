import pickle
import cloudinary
import cloudinary.uploader
from fastapi import APIRouter, Depends, UploadFile, File
from fastapi_limiter.depends import RateLimiter
from sqlalchemy.ext.asyncio import AsyncSession
from src.database.db import get_db
from src.entity.models import User
from src.schemas.user import UserResponse
from src.services.auth import auth_service
from src.conf.config import config
from src.repository import users as repositories_users

router = APIRouter(prefix="/users", tags=["users"])

cloudinary.config(
    cloud_name=config.CLD_NAME,
    api_key=config.CLD_API_KEY,
    api_secret=config.CLD_API_SECRET,
    secure=True,
)


@router.get(
    "/me",
    response_model=UserResponse,
    dependencies=[Depends(RateLimiter(times=1, seconds=20))],
)
async def read_users_me(user: User = Depends(auth_service.get_current_user)):
    """
    Retrieves the current user's information.

    :param user: User: The current user.
    :return: UserResponse: The current user's information.
    :notes: This endpoint returns the current user's information.
            The endpoint is rate-limited to 1 request per 20 seconds.
    """
    return user


@router.patch(
    "/avatar",
    response_model=UserResponse,
    dependencies=[Depends(RateLimiter(times=1, seconds=20))],
)
async def update_avatar_user(
    file: UploadFile = File(),
    user: User = Depends(auth_service.get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Updates the current user's avatar.

    :param file: UploadFile: The new avatar file.
    :param user: User: The current user.
    :param db: AsyncSession: The database session.
    :return: UserResponse: The updated user's information.
    :notes: This endpoint updates the current user's avatar.
            The endpoint is rate-limited to 1 request per 20 seconds.
            The avatar is uploaded to Cloudinary and the URL is updated in the database.
    """
    public_id = f"ContactsApp/{user.email}"
    res = cloudinary.uploader.upload(file.file, public_id=public_id, owerite=True)
    print(res)
    res_url = cloudinary.CloudinaryImage(public_id).build_url(
        width=250, height=250, crop="fill", version=res.get("version")
    )
    user = await repositories_users.update_avatar_url(user.email, res_url, db)
    auth_service.cache.set(user.email, pickle.dumps(user))
    auth_service.cache.expire(user.email, 300)
    return user
