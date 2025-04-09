from unittest.mock import Mock, patch, AsyncMock, MagicMock
import fastapi_limiter
import pytest
from fastapi.testclient import TestClient
from src.services.auth import auth_service
from src.repository.users import update_avatar_url
import logging
import asyncio

def test_get_me(client, get_token, monkeypatch):
    with patch.object(auth_service, 'cache') as redis_mock:
        redis_mock.get.return_value = None
        monkeypatch.setattr("fastapi_limiter.FastAPILimiter.redis", AsyncMock())
        monkeypatch.setattr("fastapi_limiter.FastAPILimiter.identifier", AsyncMock())
        monkeypatch.setattr("fastapi_limiter.FastAPILimiter.http_callback", AsyncMock())
        token = get_token
        headers = {"Authorization": f"Bearer {token}"}
        response = client.get("api/users/me", headers=headers)
        assert response.status_code == 200, response.text

        # Перевірка даних відповіді
        data = response.json()
        assert "id" in data
        assert "username" in data
        assert "email" in data
        assert data["email"] == "deadpool@example.com"
        assert data["username"] == "deadpool"


# @pytest.mark.asyncio
# async def test_update_avatar_user(client, get_token, monkeypatch):
#     # Мокування Redis і FastAPILimiter
#     with patch.object(auth_service, 'cache') as redis_mock:
#         redis_mock.get.return_value = None
#         redis_mock.set = MagicMock()
#         redis_mock.expire = MagicMock()
#
#         # Мокування Cloudinary
#         mock_upload = MagicMock()
#         mock_upload.side_effect = lambda *args, **kwargs: asyncio.sleep(0.1) or {"version": "12345"}
#         monkeypatch.setattr("cloudinary.uploader.upload", mock_upload)
#
#         mock_build_url = MagicMock(return_value="http://example.com/avatar.jpg")
#         monkeypatch.setattr("cloudinary.CloudinaryImage.build_url", mock_build_url)
#
#         # Мокування бази даних
#         async def mock_update_avatar_url(*args, **kwargs):
#             await asyncio.sleep(0.1)  # Тайм-аут для мокованої функції
#             return None
#
#         monkeypatch.setattr("src.repository.users.update_avatar_url", mock_update_avatar_url)
#
#         # Мокування токена
#         token = get_token
#         headers = {"Authorization": f"Bearer {token}"}
#
#         # Створення мок-файлу
#         test_file = MagicMock()
#         test_file.file = MagicMock()
#
#         # Відправка запиту на оновлення аватара
#         response = client.patch("/api/users/avatar", headers=headers, files={"file": test_file})
#
#         # Перевірка статус-коду відповіді
#         assert response.status_code == 200, response.text
#
#         # Перевірка викликів моків
#         mock_upload.assert_called_once_with(test_file.file, public_id="ContactsApp/deadpool@example.com", owerite=True)
#         mock_build_url.assert_called_once_with(width=250, height=250, crop="fill", version="12345")
#         redis_mock.set.assert_called_once()
#         redis_mock.expire.assert_called_once()