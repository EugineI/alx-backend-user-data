#!/usr/bin/env python3
""" Authentication module """
import bcrypt
import uuid
from typing import Optional
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound


def _hash_password(password: str) -> bytes:
    """
    Hashes a password, returns the hashed password
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


class Auth:
    """Auth class to interact with the authentication database."""

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Registers a user if email not already in database"""
        try:
            self._db.find_user_by(email=email)
            return None
        except NoResultFound:
            hashed_pwd = _hash_password(password)
            return self._db.add_user(email, hashed_pwd)

    def valid_login(self, email: str, password: str) -> bool:
        """Validate user login credentials"""
        try:
            user = self._db.find_user_by(email=email)

            if user and bcrypt.checkpw(password.encode('utf-8'),
                                       user.hashed_password.encode('utf-8')):
                return True
            return False
        except NoResultFound:
            return False
        except Exception:
            return False

    def _generate_uuid(self) -> str:
        """Generate a new UUID string."""
        return str(uuid.uuid4())

    def create_session(self, email: str) -> Optional[str]:
        """Create a new session for a user."""
        try:
            user = self._db.find_user_by(email=email)

            session_id = self._generate_uuid()

            self._db.update_user(user.id, session_id=session_id)

            return session_id
        except NoResultFound:
            return None
        except Exception:
            return None

    def get_user_from_session_id(self, session_id: str) -> Optional[User]:
        """Retrieve a user based on session ID."""
        if session_id is None:
            return None

        try:
            user = self._db.find_user_by(session_id=session_id)
            return user
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        """Destroy a user's session by setting session_id to None."""
        try:
            self._db.update_user(user_id, session_id=None)
        except (NoResultFound, ValueError):
            pass

    def get_reset_password_token(self, email: str) -> str:
        """Generate and store a password reset token for a user."""
        try:
            user = self._db.find_user_by(email=email)

            reset_token = self._generate_uuid()

            self._db.update_user(user.id, reset_token=reset_token)

            return reset_token
        except NoResultFound:
            raise ValueError(f"No user found with email {email}")

    def update_password(self, reset_token: str, password: str) -> None:
        """Update a user's password using a reset token."""
        try:
            user = self._db.find_user_by(reset_token=reset_token)
            hashed_password = bcrypt.hashpw(password.encode('utf-8'),
                                            bcrypt.gensalt())

            self._db.update_user(
                user.id,
                hashed_password=hashed_password.decode('utf-8'),
                reset_token=None
            )
        except NoResultFound:
            raise ValueError("Invalid reset token")
