import pickle
from datetime import datetime, timedelta, timezone
import datetime as dt
from typing import Optional

import redis
from fastapi import Depends, HTTPException, status
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from jose import JWTError, jwt

from src.database.db import get_db
from src.repository import users as repositories_users
from src.conf.config import config


class Auth:
    """
    Authentication service class.
    """
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    SECRET_KEY = config.SECRET_KEY_JWT
    ALGORITHM = config.ALGORITHM
    cache = redis.Redis(
        host=config.REDIS_DOMAIN,
        port=config.REDIS_PORT,
        db=0,
        password=config.REDIS_PASSWORD,
    )

    def verify_password(self, plain_password, hashed_password):
        """
        Verify a plain password against a hashed password.

        :param plain_password: str: The plain password to verify.
        :param hashed_password: str: The hashed password to verify against.
        :return: bool: True if the passwords match, False otherwise.
        """
        return self.pwd_context.verify(plain_password, hashed_password)

    def get_password_hash(self, password: str):
        """
        Get the hashed version of a password.

        :param password: str: The password to hash.
        :return: str: The hashed password.
        """
        return self.pwd_context.hash(password)

    oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login")

    # define a function to generate a new access token
    async def create_access_token(
        self, data: dict, expires_delta: Optional[float] = None
    ):
        """
        Create a new access token.

        :param data: dict: The data to encode in the token.
        :param expires_delta: Optional[float]: The time in seconds until the token expires.
        :return: str: The encoded access token.
        """
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.now(timezone.utc) + timedelta(seconds=expires_delta)
        else:
            expire = datetime.now(timezone.utc) + timedelta(minutes=15)
        to_encode.update(
            {"iat": datetime.now(timezone.utc), "exp": expire, "scope": "access_token"}
        )
        encoded_access_token = jwt.encode(
            to_encode, self.SECRET_KEY, algorithm=self.ALGORITHM
        )
        return encoded_access_token

    async def create_refresh_token(
        self, data: dict, expires_delta: Optional[float] = None
    ):
        """
        Create a new refresh token.

        :param data: dict: The data to encode in the token.
        :param expires_delta: Optional[float]: The time in seconds until the token expires.
        :return: str: The encoded refresh token.
        """
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.now(timezone.utc) + timedelta(seconds=expires_delta)
        else:
            expire = datetime.now(timezone.utc) + timedelta(days=7)
        to_encode.update(
            {"iat": datetime.now(timezone.utc), "exp": expire, "scope": "refresh_token"}
        )
        encoded_refresh_token = jwt.encode(
            to_encode, self.SECRET_KEY, algorithm=self.ALGORITHM
        )
        return encoded_refresh_token

    async def decode_refresh_token(self, refresh_token: str):
        """
        Decode a refresh token and extract the email address.

        :param refresh_token: str: The refresh token to decode.
        :return: str: The email address extracted from the token.
        :raises HTTPException: If the token is invalid or cannot be decoded.
        """
        try:
            payload = jwt.decode(
                refresh_token, self.SECRET_KEY, algorithms=[self.ALGORITHM]
            )
            if payload["scope"] == "refresh_token":
                email = payload["sub"]
                return email
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid scope for token",
            )
        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
            )

    async def get_current_user(
        self, token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)
    ):
        """
        Get the current user based on the provided token.

        :param token: str: The token to use for authentication.
        :param db: AsyncSession: The database session to use.
        :return: User: The current user.
        :raises HTTPException: If the token is invalid or cannot be decoded.
        """
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

        try:
            # Decode JWT
            payload = jwt.decode(token, self.SECRET_KEY, algorithms=[self.ALGORITHM])
            if payload["scope"] == "access_token":
                email = payload["sub"]
                if email is None:
                    raise credentials_exception
            else:
                raise credentials_exception
        except JWTError as e:
            raise credentials_exception

        user_hash = str(email)

        user = self.cache.get(user_hash)

        if user is None:
            print("User from database")
            user = await repositories_users.get_user_by_email(email, db)
            if user is None:
                raise credentials_exception
            self.cache.set(user_hash, pickle.dumps(user))
            self.cache.expire(user_hash, 300)
        else:
            print("User from cache")
            user = pickle.loads(user)
        return user

    def create_email_token(self, data: dict):
        """
        Create a token for email verification.

        :param data: dict: The data to encode in the token.
        :return: str: The encoded token.
        """
        to_encode = data.copy()
        expire = datetime.now(dt.timezone.utc) + timedelta(days=7)
        to_encode.update({"iat": datetime.now(dt.timezone.utc), "exp": expire})
        token = jwt.encode(to_encode, self.SECRET_KEY, algorithm=self.ALGORITHM)
        return token

    async def get_email_from_token(self, token: str):
        """
        Extract the email address from a token.

        :param token: str: The token to decode.
        :return: str: The email address extracted from the token.
        :raises HTTPException: If the token is invalid or cannot be decoded.
        """
        try:
            payload = jwt.decode(token, self.SECRET_KEY, algorithms=[self.ALGORITHM])
            email = payload["sub"]
            return email
        except JWTError as e:
            print(e)
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Invalid token for email verification",
            )

    async def update_password(self, email: str, new_password: str, db: AsyncSession):
        """
        Update the password of a user in the database.

        :param email: str: The email address of the user.
        :param new_password: str: The new password to set.
        :param db: AsyncSession: The database session to use.
        :raises HTTPException: If the user is not found or the password cannot be updated.
        """
        user = await repositories_users.get_user_by_email(email, db)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )

        hashed_password = self.get_password_hash(new_password)
        await repositories_users.update_password(user, hashed_password, db)


auth_service = Auth()
