import pytest
from unittest.mock import Mock, patch, AsyncMock, ANY
from fastapi import status, HTTPException
from src.conf import messages
from src.services.auth import auth_service
from datetime import datetime, date


# Тест на отримання контактів, якщо не знайдені

def test_get_contacts_not_found(client, get_token):
    with patch.object(auth_service, 'cache') as redis_mock:
        redis_mock.get.return_value = None
        token = get_token
        headers = {"Authorization": f"Bearer {token}"}
        response = client.get("api/contacts", headers=headers)
        assert response.status_code == 200, response.text
        data = response.json()
        assert len(data) == 0


# Тест на отримання контактів

def test_get_contacts_found(client, get_token, monkeypatch):
    # Мокування Redis і FastAPILimiter
    with patch.object(auth_service, 'cache') as redis_mock:
        redis_mock.get.return_value = None
        monkeypatch.setattr("fastapi_limiter.FastAPILimiter.redis", AsyncMock())
        monkeypatch.setattr("fastapi_limiter.FastAPILimiter.identifier",
                            AsyncMock())
        monkeypatch.setattr("fastapi_limiter.FastAPILimiter.http_callback",
                            AsyncMock())

    token = get_token
    headers = {"Authorization": f"Bearer {token}"}

    # Емулюємо список контактів, які повертає репозиторій
    mock_contacts = [
        {
            "id": 1,
            "first_name": "John",
            "last_name": "Doe",
            "email": "john.doe@example.com",
            "phone_number": "1234512345",
            "birthday": "1990-04-07",
            "created_at": "2023-01-01T12:00:00",
            "updated_at": "2023-01-02T12:00:00",
        },
        {
            "id": 2,
            "first_name": "Jane",
            "last_name": "Doe",
            "email": "jane.doe@example.com",
            "phone_number": "6789067890",
            "birthday": "1995-04-06",
            "created_at": "2023-01-03T12:00:00",
            "updated_at": "2023-01-04T12:00:00",
        },
    ]

    # Мокаємо функцію repositories_contacts.get_contacts
    with patch("src.repository.contacts.get_contacts",
               new_callable=AsyncMock) as mock_get_contacts:
        mock_get_contacts.return_value = mock_contacts  # Емулюємо повернення списку контактів

        # Викликаємо GET-запит для отримання контактів
        response = client.get("/api/contacts", headers=headers)
        assert response.status_code == 200, response.text
        data = response.json()

        # Перевіряємо, що кількість контактів відповідає очікуваній
        assert len(data) == len(mock_contacts)

        # Перевіряємо, що всі контакти створені коректно
        for i, contact in enumerate(mock_contacts):
            assert data[i]["id"] == contact["id"]
            assert data[i]["first_name"] == contact["first_name"]
            assert data[i]["last_name"] == contact["last_name"]
            assert data[i]["email"] == contact["email"]
            assert data[i]["phone_number"] == contact["phone_number"]
            assert data[i]["birthday"] == contact["birthday"]
            assert data[i]["created_at"] == contact["created_at"]
            assert data[i]["updated_at"] == contact["updated_at"]


# Тест створення контакту

def test_create_contact_success(client, get_token, monkeypatch):
    # Мокування Redis і FastAPI Limiter
    with patch.object(auth_service, 'cache') as redis_mock:
        redis_mock.get.return_value = None
        monkeypatch.setattr("fastapi_limiter.FastAPILimiter.redis", AsyncMock())
        monkeypatch.setattr("fastapi_limiter.FastAPILimiter.identifier",
                            AsyncMock())
        monkeypatch.setattr("fastapi_limiter.FastAPILimiter.http_callback",
                            AsyncMock())
    token = get_token
    headers = {"Authorization": f"Bearer {token}"}

    # Дані контакту для створення
    create_body = {
        "first_name": "John",
        "last_name": "Doe",
        "email": "john.doe@example.com",
        "phone_number": "1234512345",
        "birthday": "1990-04-07",
        "additional_info": "Test additional info",
    }

    # Моковані дані створеного контакту
    created_contact = {
        "id": 1,
        "first_name": create_body["first_name"],
        "last_name": create_body["last_name"],
        "email": create_body["email"],
        "phone_number": create_body["phone_number"],
        "birthday": create_body["birthday"],
        "additional_info": create_body["additional_info"],
        "created_at": "2023-01-01T12:00:00",
        "updated_at": "2023-01-02T12:00:00",
    }

    # Мокаємо функцію repositories_contacts.create_contact
    with patch("src.repository.contacts.create_contact",
               new_callable=AsyncMock) as mock_create_contact:
        mock_create_contact.return_value = created_contact  # Емулюємо повернення створеного контакту

        # Викликаємо POST-запит для створення контакту
        response = client.post("/api/contacts", headers=headers,
                               json=create_body)
        assert response.status_code == status.HTTP_201_CREATED, response.text
        data = response.json()

        # Перевіряємо, що повернуті дані відповідають очікуваним
        assert data["id"] == created_contact["id"]
        assert data["first_name"] == created_contact["first_name"]
        assert data["last_name"] == created_contact["last_name"]
        assert data["email"] == created_contact["email"]
        assert data["phone_number"] == created_contact["phone_number"]
        assert data["birthday"] == created_contact["birthday"]
        assert data["additional_info"] == created_contact["additional_info"]
        assert data["created_at"] == created_contact["created_at"]
        assert data["updated_at"] == created_contact["updated_at"]


# Тест створення контакту (помилка сервера)
def test_create_contact_server_error(client, get_token, monkeypatch):
    # Мокування Redis і FastAPI Limiter
    with patch.object(auth_service, 'cache') as redis_mock:
        redis_mock.get.return_value = None
        monkeypatch.setattr("fastapi_limiter.FastAPILimiter.redis", AsyncMock())
        monkeypatch.setattr("fastapi_limiter.FastAPILimiter.identifier",
                            AsyncMock())
        monkeypatch.setattr("fastapi_limiter.FastAPILimiter.http_callback",
                            AsyncMock())

    token = get_token
    headers = {"Authorization": f"Bearer {token}"}

    create_body = {
        "first_name": "John",
        "last_name": "Doe",
        "email": "john.doe@example.com",
        "phone_number": "1234512345",
        "birthday": "1990-04-07",
        "additional_info": "Test additional info",
    }

    # Мокаємо функцію repositories_contacts.create_contact
    with patch("src.repository.contacts.create_contact",
               new_callable=AsyncMock) as mock_create_contact:
        mock_create_contact.side_effect = Exception(
            "Unexpected error")  # Емулюємо виняток

        # Викликаємо POST-запит для створення контакту
        response = client.post("/api/contacts", headers=headers,
                               json=create_body)
        assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR, response.text

        # Перевіряємо деталі помилки
        data = response.json()
        assert data["detail"] == messages.INTERNAL_SERVER_ERROR


# Тест отримання контакту

def test_get_contact_found(client, get_token, monkeypatch):
    # Мокування Redis і FastAPILimiter
    with patch.object(auth_service, 'cache') as redis_mock:
        redis_mock.get.return_value = None
        monkeypatch.setattr("fastapi_limiter.FastAPILimiter.redis", AsyncMock())
        monkeypatch.setattr("fastapi_limiter.FastAPILimiter.identifier",
                            AsyncMock())
        monkeypatch.setattr("fastapi_limiter.FastAPILimiter.http_callback",
                            AsyncMock())
    token = get_token
    headers = {"Authorization": f"Bearer {token}"}

    # Моковані дані контакту
    mock_contact = {
        "id": 1,
        "first_name": "John",
        "last_name": "Doe",
        "email": "john.doe@example.com",
        "phone_number": "1234512345",
        "birthday": "1990-04-07",
        "created_at": "2023-01-01T12:00:00",
        "updated_at": "2023-01-02T12:00:00",
    }

    # Мокаємо функцію repositories_contacts.get_contact
    with patch("src.repository.contacts.get_contact",
               new_callable=AsyncMock) as mock_get_contact:
        mock_get_contact.return_value = mock_contact  # Емулюємо повернення контакту

        # Викликаємо GET-запит для отримання контакту
        response = client.get(f"/api/contacts/{mock_contact['id']}",
                              headers=headers)
        assert response.status_code == 200, response.text
        data = response.json()

        # Перевіряємо, що дані контакту відповідають очікуваним
        assert data["id"] == mock_contact["id"]
        assert data["first_name"] == mock_contact["first_name"]
        assert data["last_name"] == mock_contact["last_name"]
        assert data["email"] == mock_contact["email"]
        assert data["phone_number"] == mock_contact["phone_number"]
        assert data["birthday"] == mock_contact["birthday"]
        assert data["created_at"] == mock_contact["created_at"]
        assert data["updated_at"] == mock_contact["updated_at"]


# Тест отримання контакту за його ID не існує

def test_get_contact_is_none(client, get_token):
    token = get_token
    headers = {"Authorization": f"Bearer {token}"}

    non_existent_id = 999  # Неіснуючий ID контакту

    # Мокаємо функцію repositories_contacts.get_contact
    with patch("src.repository.contacts.get_contact",
               new_callable=AsyncMock) as mock_get_contact:
        # Емулюємо повернення None для неіснуючого ID
        mock_get_contact.return_value = None

        # Викликаємо GET-запит для неіснуючого ID
        response = client.get(f"/api/contacts/{non_existent_id}",
                              headers=headers)

        # Перевіряємо статус-код (404 NOT FOUND)
        assert response.status_code == status.HTTP_404_NOT_FOUND, response.text

        # Перевіряємо повідомлення про помилку
        data = response.json()
        assert data["detail"] == messages.CONTACT_NOT_FOUND

        # Перевіряємо, що функцію get_contact викликали з правильними параметрами
        mock_get_contact.assert_called_once_with(non_existent_id, ANY, ANY)


# Тест редагування контакту

def test_update_contact_success(client, get_token):
    token = get_token
    headers = {"Authorization": f"Bearer {token}"}

    # Моковані дані для оновлення контакту
    contact_id = 1
    update_body = {
        "first_name": "Jane",
        "last_name": "Doe",
        "email": "jane.doe@example.com",
        "phone_number": "9876543210",
        "birthday": "1995-06-15",
        "additional_info": "Updated contact info",
    }

    # Дані контакту після оновлення
    updated_contact = {
        "id": contact_id,
        "first_name": update_body["first_name"],
        "last_name": update_body["last_name"],
        "email": update_body["email"],
        "phone_number": update_body["phone_number"],
        "birthday": update_body["birthday"],
        "created_at": "2023-01-01T12:00:00",
        "updated_at": "2023-01-02T12:00:00",
    }

    # Мокаємо функцію repositories_contacts.update_contact
    with patch("src.repository.contacts.update_contact",
               new_callable=AsyncMock) as mock_update_contact:
        mock_update_contact.return_value = updated_contact  # Емулюємо повернення оновленого контакту

        # Викликаємо PUT-запит для оновлення контакту
        response = client.put(f"/api/contacts/{contact_id}", headers=headers,
                              json=update_body)
        assert response.status_code == 200, response.text
        data = response.json()

        # Перевіряємо, що повернуті дані відповідають очікуваним
        assert data["id"] == updated_contact["id"]
        assert data["first_name"] == updated_contact["first_name"]
        assert data["last_name"] == updated_contact["last_name"]
        assert data["email"] == updated_contact["email"]
        assert data["phone_number"] == updated_contact["phone_number"]
        assert data["birthday"] == updated_contact["birthday"]
        assert data["created_at"] == updated_contact["created_at"]
        assert data["updated_at"] == updated_contact["updated_at"]


# Тест оновлення неіснуючого контакту
def test_update_contact_not_found(client, get_token):
    token = get_token
    headers = {"Authorization": f"Bearer {token}"}

    # Дані для оновлення контакту
    contact_id = 999  # Неіснуючий ID
    update_body = {
        "first_name": "Jane",
        "last_name": "Doe",
        "email": "jane.doe@example.com",
        "phone_number": "9876543210",
        "birthday": "1995-06-15",
    }

    # Мокаємо функцію repositories_contacts.update_contact
    with patch("src.repository.contacts.update_contact",
               new_callable=AsyncMock) as mock_update_contact:
        mock_update_contact.return_value = None  # Емулюємо, що контакт не знайдено

        # Викликаємо PUT-запит для оновлення неіснуючого контакту
        response = client.put(f"/api/contacts/{contact_id}", headers=headers,
                              json=update_body)
        assert response.status_code == status.HTTP_404_NOT_FOUND, response.text

        # Перевіряємо деталі помилки
        data = response.json()
        assert data["detail"] == messages.CONTACT_NOT_FOUND


# Тест видалення контакту
def test_delete_contact(client, get_token, monkeypatch):
    with patch.object(auth_service, 'cache') as redis_mock:
        redis_mock.get.return_value = None
        monkeypatch.setattr("fastapi_limiter.FastAPILimiter.redis", AsyncMock())
        monkeypatch.setattr("fastapi_limiter.FastAPILimiter.identifier",
                            AsyncMock())
        monkeypatch.setattr("fastapi_limiter.FastAPILimiter.http_callback",
                            AsyncMock())
    token = get_token
    headers = {"Authorization": f"Bearer {token}"}

    # Емулюємо створення контакту
    body = {"first_name": "John", "last_name": "Doe",
            "email": "6V7ZM@example.com",
            "phone_number": "1234567890", "birthday": "1990-04-07"}
    response = client.post("api/contacts", headers=headers, json=body)
    assert response.status_code == 201, response.text
    data = response.json()
    contact_id = data["id"]

    # Мокаємо функцію repositories_contacts.delete_contact
    with patch("src.repository.contacts.delete_contact",
               new_callable=AsyncMock) as mock_delete_contact:
        mock_delete_contact.return_value = {
            "id": contact_id,
            "first_name": "John",
            "last_name": "Doe",
            "email": "6V7ZM@example.com",
            "phone_number": "1234567890",
            "birthday": "1990-04-07",
        }

        # Викликаємо DELETE запит
        response = client.delete(f"api/contacts/{contact_id}", headers=headers)
        assert response.status_code == 204, response.text


# Тест отримати майбутні дні народження

def test_get_upcoming_birthdays_success(client, get_token):
    token = get_token
    headers = {"Authorization": f"Bearer {token}"}

    # Емулюємо список контактів із днями народження
    mock_contacts = [
        {
            "first_name": "Alice",
            "last_name": "Smith",
            "birthday": date(1990, 4, 10).isoformat(),
            "created_at": datetime(2025, 4, 1, 12, 0, 0).isoformat(),
            "updated_at": datetime(2025, 4, 5, 12, 0, 0).isoformat(),
        },
        {
            "first_name": "Bob",
            "last_name": "Johnson",
            "birthday": date(1985, 4, 15).isoformat(),
            "created_at": datetime(2025, 4, 2, 12, 0, 0).isoformat(),
            "updated_at": datetime(2025, 4, 6, 12, 0, 0).isoformat(),
        },
    ]

    # Мокаємо функцію get_upcoming_birthdays
    with patch("src.repository.contacts.get_upcoming_birthdays",
               new_callable=AsyncMock) as mock_get_birthdays:
        mock_get_birthdays.return_value = mock_contacts

        response = client.get("/api/contacts/birthdays", headers=headers)

        # Перевіряємо статус-код
        assert response.status_code == 200
        data = response.json()

        # Перевіряємо, що відповідь відповідає очікуваній
        assert len(data) == len(mock_contacts)
        for i, contact in enumerate(mock_contacts):
            assert data[i]["first_name"] == contact["first_name"]
            assert data[i]["last_name"] == contact["last_name"]
            assert data[i]["birthday"] == contact["birthday"]
            assert data[i]["created_at"] == contact["created_at"]
            assert data[i]["updated_at"] == contact["updated_at"]


# Тест на обробку помилки
def test_get_upcoming_birthdays_exception(client, get_token):
    token = get_token
    headers = {"Authorization": f"Bearer {token}"}

    # Емулюємо виклик, що викликає виняток
    with patch("src.repository.contacts.get_upcoming_birthdays",
               new_callable=AsyncMock) as mock_get_birthdays:
        mock_get_birthdays.side_effect = Exception("Database Error")

        response = client.get("/api/contacts/birthdays", headers=headers)

        # Перевіряємо статус-код
        assert response.status_code == 500
        data = response.json()

        # Перевіряємо повідомлення про помилку
        assert data["detail"] == messages.INTERNAL_SERVER_ERROR


def test_get_upcoming_birthdays_http_exception(client, get_token):
    token = get_token
    headers = {"Authorization": f"Bearer {token}"}

    # Емулюємо виклик, що викликає HTTPException
    with patch("src.repository.contacts.get_upcoming_birthdays",
               new_callable=AsyncMock) as mock_get_birthdays:
        mock_get_birthdays.side_effect = HTTPException(
            status_code=404, detail="Contact not found"
        )

        response = client.get("/api/contacts/birthdays", headers=headers)

        # Перевіряємо, що виняток правильно обробляється
        assert response.status_code == 404
        data = response.json()
        assert data["detail"] == "Contact not found"
