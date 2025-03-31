from fastapi import Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from libgravatar import Gravatar

from src.database.db import get_db
from src.entity.models import User
from src.schemas.user import UserSchema


async def get_user_by_email(email: str, db: AsyncSession = Depends(get_db)):
    """
    Retrieve user by email from the database.

    Parameters:
        email (str): The email address of the user to retrieve.
        db (AsyncSession): The database session.

    Returns:
        User: The user object if found, otherwise None.
    """
    stmt = select(User).filter_by(email=email)
    user = await db.execute(stmt)
    user = user.scalar_one_or_none()
    return user


async def create_user(body: UserSchema, db: AsyncSession = Depends(get_db)):
    """
    Create a new user in the database.

    Parameters:
        body (UserSchema): The user data to create.
        db (AsyncSession): The database session.

    Returns:
        User: The created user object, containing user's data and avatar URL.
    """
    avatar = None
    try:
        g = Gravatar(body.email)
        avatar = g.get_image()
    except Exception as err:
        print(err)

    new_user = User(**body.model_dump(), avatar=avatar)
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    return new_user


async def update_token(user: User, token: str | None, db: AsyncSession):
    """
    Updates a user's refresh token.

    Updates the refresh token for the given user in the database.

    Parameters:
        user (User): The user object to update.
        token (str | None): The new refresh token.
        db (AsyncSession): The database session.

    Returns:
        None
    """
    user.refresh_token = token
    await db.commit()


async def confirmed_email(email: str, db: AsyncSession) -> None:
    """
    Confirm a user's email address.

    Marks a user's email address as confirmed in the database.

    Parameters:
        email (str): The email address to confirm.
        db (AsyncSession): The database session.

    Returns:
        None
    """
    user = await get_user_by_email(email, db)
    user.confirmed = True
    await db.commit()


async def update_avatar_url(email: str, url: str | None, db: AsyncSession) -> User:
    """
    Update a user's avatar URL.

    Updates the avatar URL for a user in the database.

    Parameters:
        email (str): The email address of the user to update.
        url (str | None): The new avatar URL.
        db (AsyncSession): The database session.

    Returns:
        User: The updated user object.
    """
    user = await get_user_by_email(email, db)
    user.avatar = url
    await db.commit()
    await db.refresh(user)
    return user


async def update_password(user: User, hashed_password: str, db: AsyncSession) -> None:
    """
    Update a user's password in the database.

    Updates the password for a user in the database.

    Parameters:
        user (User): The user object to update.
        hashed_password (str): The new hashed password.
        db (AsyncSession): The database session.

    Returns:
        None
    """
    user.password = hashed_password  # Оновлюємо поле пароля
    db.add(user)  # Додаємо користувача в сесію для оновлення
    await db.commit()  # Фіксуємо зміни в базі
    await db.refresh(user)  # Оновлюємо об'єкт користувача після змін
