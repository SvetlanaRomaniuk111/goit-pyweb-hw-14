import unittest
from unittest.mock import AsyncMock, MagicMock

from sqlalchemy import select, and_, func
from sqlalchemy.ext.asyncio import AsyncSession
from src.entity.models import Contact, User
from src.schemas.contact import ContactCreateSchema, ContactUpdateSchema
from src.repository.contacts import get_contacts, get_contact, create_contact, \
    update_contact, delete_contact, get_upcoming_birthdays
from datetime import date, timedelta
from dateutil.relativedelta import relativedelta



class TestContactsRepository(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.user = User(id=1, username="test_user", password="qwerty",
                         confirmed=True)
        self.session = AsyncMock(spec=AsyncSession)

    async def test_get_contacts(self):
        limit = 10
        offset = 0
        first_name = ""
        last_name = ""
        email = ""

        contacts = [
            Contact(id=1, first_name="John", last_name="Doe",
                    email="6V7ZM@example.com", phone_number="1234512345",
                    birthday="1990-04-07", user=self.user),
            Contact(id=2, first_name="Jane", last_name="Doe",
                    email="M0p2o@example.com", phone_number="6789067890",
                    birthday="1995-04-06", user=self.user),
        ]

        mocked_contacts = MagicMock()
        mocked_contacts.scalars().all.return_value = contacts
        self.session.execute.return_value = mocked_contacts

        result = await get_contacts(limit, offset, first_name, last_name, email,
                                    self.session, self.user)

        self.assertEqual(result, contacts)

    async def test_get_contacts_not_found(self):
        limit = 10
        offset = 0
        first_name = ""
        last_name = ""
        email = ""

        mocked_contacts = MagicMock()
        mocked_contacts.scalars().all.return_value = []
        self.session.execute.return_value = mocked_contacts

        result = await get_contacts(limit, offset, first_name, last_name, email,
                                    self.session, self.user)

        self.assertEqual(result, [])

    async def test_get_contacts_filter_by_first_name(self):
        limit = 10
        offset = 0
        first_name = "Jane"
        last_name = ""
        email = ""

        # Список контактів у базі
        contacts = [
            Contact(id=1, first_name="John", last_name="Doe",
                    email="john@example.com", phone_number="1234567890",
                    birthday="1990-01-01", user=self.user),
            Contact(id=2, first_name="Jane", last_name="Smith",
                    email="jane@example.com", phone_number="0987654321",
                    birthday="1995-03-25", user=self.user),
        ]

        # Мокуємо результат фільтрації
        mocked_contacts = MagicMock()
        mocked_contacts.scalars().all.return_value = [
            contacts[1]]  # Очікуємо тільки контакт "Jane"
        self.session.execute.return_value = mocked_contacts

        # Виклик функції
        result = await get_contacts(limit, offset, first_name, last_name,
                                    email, self.session, self.user)

        # Перевірки
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], contacts[1])

    async def test_get_contacts_filter_by_email(self):
        limit = 10
        offset = 0
        first_name = ""
        last_name = ""
        email = "john@example.com"

        contacts = [
            Contact(id=1, first_name="John", last_name="Doe",
                    email="john@example.com", phone_number="1234567890",
                    birthday="1990-01-01", user=self.user),
            Contact(id=2, first_name="Jane", last_name="Smith",
                    email="jane@example.com", phone_number="0987654321",
                    birthday="1995-03-25", user=self.user),
        ]

        mocked_contacts = MagicMock()
        mocked_contacts.scalars().all.return_value = [
            contacts[0]]  # Очікуємо тільки контакт "John"
        self.session.execute.return_value = mocked_contacts

        result = await get_contacts(limit, offset, first_name, last_name,
                                    email, self.session, self.user)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], contacts[0])

    async def test_get_contacts_filter_by_last_name(self):
        limit = 10
        offset = 0
        first_name = ""
        last_name = "Smith"
        email = ""

        contacts = [
            Contact(id=1, first_name="John", last_name="Doe",
                    email="john@example.com", phone_number="1234567890",
                    birthday="1990-01-01", user=self.user),
            Contact(id=2, first_name="Jane", last_name="Smith",
                    email="jane@example.com", phone_number="0987654321",
                    birthday="1995-03-25", user=self.user),
        ]

        mocked_contacts = MagicMock()
        mocked_contacts.scalars().all.return_value = [
            contacts[1]]  # Очікуємо тільки контакт із прізвищем "Smith"
        self.session.execute.return_value = mocked_contacts

        result = await get_contacts(limit, offset, first_name, last_name,
                                    email, self.session, self.user)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], contacts[1])

    async def test_get_contacts_multiple_filters(self):
        limit = 10
        offset = 0
        first_name = "Jane"
        last_name = "Smith"
        email = "jane@example.com"

        contacts = [
            Contact(id=1, first_name="John", last_name="Doe",
                    email="john@example.com", phone_number="1234567890",
                    birthday="1990-01-01", user=self.user),
            Contact(id=2, first_name="Jane", last_name="Smith",
                    email="jane@example.com", phone_number="0987654321",
                    birthday="1995-03-25", user=self.user),
        ]

        mocked_contacts = MagicMock()
        # Очікуємо тільки контакт, який відповідає всім фільтрам
        mocked_contacts.scalars().all.return_value = [contacts[1]]
        self.session.execute.return_value = mocked_contacts

        result = await get_contacts(limit, offset, first_name, last_name,
                                    email, self.session, self.user)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], contacts[1])

    async def test_get_contact(self):
        contact_id = 1

        contact = Contact(id=1, first_name="John", last_name="Doe",
                          email="6V7ZM@example.com", phone_number="1234512345",
                          birthday="1990-04-07", user=self.user)

        mocked_contact = MagicMock()
        mocked_contact.scalar_one_or_none.return_value = contact
        self.session.execute.return_value = mocked_contact

        result = await get_contact(contact_id, self.session, self.user)

        self.assertEqual(result, contact)

    async def test_get_contact_not_found(self):
        contact_id = 999

        mocked_contact = MagicMock()
        mocked_contact.scalar_one_or_none.return_value = None
        self.session.execute.return_value = mocked_contact

        result = await get_contact(contact_id, self.session, self.user)

        self.assertIsNone(result)

    async def test_get_contact_db_error(self):
        contact_id = 1
        self.session.execute.side_effect = Exception(
            "Database error")  # Імітація помилки

        with self.assertRaises(Exception) as context:
            await get_contact(contact_id, self.session, self.user)

        self.assertEqual(str(context.exception),
                         "Database error")  # Перевірка тексту виключення
        self.session.execute.assert_called_once()  # Перевірка виклику execute

    async def test_create_contact(self):
        body = ContactCreateSchema(
            first_name="John",
            last_name="Doe",
            email="6V7ZM@example.com",
            phone_number="1234512345",
            birthday=date.fromisoformat("1990-04-07")
        )

        # Мокування методів сесії
        self.session.add = MagicMock()  # Мокування `add`
        self.session.commit = AsyncMock()  # Мокування `commit`
        self.session.refresh = AsyncMock()  # Мокування `refresh`

        result = await create_contact(body, self.session, self.user)

        self.assertIsInstance(result, Contact)
        self.assertEqual(result.first_name, body.first_name)
        self.assertEqual(result.last_name, body.last_name)
        self.assertEqual(result.email, body.email)
        self.assertEqual(result.phone_number, body.phone_number)
        self.assertEqual(result.birthday, body.birthday)
        self.assertEqual(result.user, self.user)

        # Перевірка викликів мокованих методів
        self.session.add.assert_called_once_with(result)
        self.session.commit.assert_called_once()
        self.session.refresh.assert_called_once_with(result)

    async def test_create_contact_db_error(self):
        body = ContactCreateSchema(
            first_name="John",
            last_name="Doe",
            email="6V7ZM@example.com",
            phone_number="1234512345",
            birthday=date.fromisoformat("1990-04-07")
        )

        # Імітація помилки в `commit`
        self.session.commit.side_effect = Exception("Database error")

        with self.assertRaises(Exception) as context:
            await create_contact(body, self.session, self.user)

        self.assertEqual(str(context.exception),
                         "Database error")  # Перевірка тексту виключення

        # Перевірка викликання методів
        self.session.add.assert_called_once()
        self.session.commit.assert_called_once()
        self.session.refresh.assert_not_called()  # `refresh` не має викликатися при помилці

    async def test_update_contact(self):
        contact_id = 1
        body = ContactUpdateSchema(first_name="Updated Name",
                                   last_name="Updated Last Name",
                                   email="updated_email@example.com",
                                   phone_number="5555555555",
                                   birthday=date.fromisoformat("2000-01-01"))

        # Створюємо існуючий об'єкт контакту
        existing_contact = Contact(
            id=1,
            first_name="John",
            last_name="Doe",
            email="6V7ZM@example.com",
            phone_number="1234512345",
            birthday="1990-04-07",
            user=self.user
        )

        # Мокування виконання запиту
        mocked_contact = MagicMock()
        mocked_contact.scalar_one_or_none.return_value = existing_contact
        self.session.execute.return_value = mocked_contact

        # Мокування методів commit та refresh
        self.session.commit = AsyncMock()
        self.session.refresh = AsyncMock()

        # Виклик функції
        result = await update_contact(contact_id, body, self.session, self.user)

        # Перевірки
        self.assertIsInstance(result, Contact)
        self.assertEqual(result.first_name, body.first_name)
        self.assertEqual(result.last_name, body.last_name)
        self.assertEqual(result.email, body.email)
        self.assertEqual(result.phone_number, body.phone_number)
        self.assertEqual(result.birthday, body.birthday)
        self.session.commit.assert_called_once()
        self.session.refresh.assert_called_once_with(existing_contact)

    async def test_update_contact_not_found(self):
        contact_id = 999

        # Мокування: контакт не знайдено
        mocked_contact = MagicMock()
        mocked_contact.scalar_one_or_none.return_value = None
        self.session.execute.return_value = mocked_contact

        # Виклик функції
        result = await update_contact(contact_id, ContactUpdateSchema(first_name="test", last_name="user"),
                                      self.session, self.user)

        # Перевірки
        self.assertIsNone(
            result)  # Якщо контакт не знайдено, має повернутися None
        self.session.commit.assert_not_called()  # commit не повинен викликатися
        self.session.refresh.assert_not_called()  # refresh не повинен викликатися

    from unittest.mock import ANY

    async def test_delete_contact(self):
        contact_id = 1

        # Створюємо існуючий об'єкт контакту
        existing_contact = Contact(
            id=1,
            first_name="John",
            last_name="Doe",
            email="6V7ZM@example.com",
            phone_number="1234512345",
            birthday="1990-04-07",
            user=self.user
        )

        # Мокування виконання запиту
        mocked_contact = MagicMock()
        mocked_contact.scalar_one_or_none.return_value = existing_contact
        self.session.execute.return_value = mocked_contact

        # Мокування методів commit та delete
        self.session.commit = AsyncMock()
        self.session.delete = AsyncMock()

        # Очікуваний SQL-запит
        stmt = select(Contact).filter_by(id=contact_id, user=self.user)

        # Виклик функції
        result = await delete_contact(contact_id, self.session, self.user)

        # Отримання фактичного запиту
        actual_stmt = self.session.execute.call_args[0][
            0]  # Аргумент, переданий у `execute`

        # Перевірки
        self.assertIsInstance(result, Contact)  # Має повернути об'єкт Contact
        self.assertEqual(str(actual_stmt),
                         str(stmt))  # Порівнюємо текстовий вигляд запитів
        self.assertEqual(result,
                         existing_contact)  # Має повернути існуючий контакт
        self.session.delete.assert_called_once_with(
            existing_contact)  # Перевірка виклику `delete`
        self.session.commit.assert_called_once()  # Перевірка виклику `commit`

    async def test_delete_contact_not_found(self):
        contact_id = 999

        # Мокування: контакт не знайдено
        mocked_contact = MagicMock()
        mocked_contact.scalar_one_or_none.return_value = None
        self.session.execute.return_value = mocked_contact

        # Виклик функції
        result = await delete_contact(contact_id, self.session, self.user)

        # Перевірки
        self.assertIsNone(
            result)  # Якщо контакт не знайдено, має повернутися None
        self.session.commit.assert_not_called()  # commit не повинен викликатися
        self.session.delete.assert_not_called()  # delete не повинен викликатися

    async def test_get_upcoming_birthdays_found(self):
        today = date.today()
        end_date = today + timedelta(days=7)

        # Створюємо контакти з днями народження в межах наступних 7 днів
        contact1 = Contact(
            id=1,
            first_name="John",
            last_name="Doe",
            email="john.doe@example.com",
            phone_number="1234567890",
            birthday = today + relativedelta(days=1),
            # День народження завтра
            user=self.user
        )
        contact2 = Contact(
            id=2,
            first_name="Jane",
            last_name="Doe",
            email="jane.doe@example.com",
            phone_number="0987654321",
            birthday = today + relativedelta(days=6),
            # День народження через 6 днів
            user=self.user
        )

        # Мокування результату
        mocked_result = MagicMock()
        mocked_result.scalars().all.return_value = [contact1, contact2]
        self.session.execute.return_value = mocked_result

        # Очікуваний SQL-запит
        stmt = select(Contact).filter(
            and_(
                func.to_char(Contact.birthday, 'MM-DD') >= func.to_char(today,
                                                                        'MM-DD'),
                func.to_char(Contact.birthday, 'MM-DD') <= func.to_char(
                    end_date, 'MM-DD'),
                Contact.user == self.user
            )
        )

        # Виклик функції
        result = await get_upcoming_birthdays(self.session, self.user)

        # Перевірка текстового вигляду SQL-запиту
        actual_query = str(self.session.execute.call_args[0][
                               0])  # Отримуємо запит, переданий у `execute`
        self.assertEqual(actual_query,
                         str(stmt))  # Порівнюємо текстове представлення запитів

        # Перевірки результатів
        self.assertEqual(result, [contact1,
                                  contact2])  # Перевіряємо, що повернувся список з очікуваними контактами
        self.session.execute.assert_called_once()  # Перевіряємо, що `execute` викликали

    async def test_get_upcoming_birthdays_not_found(self):
        today = date.today()
        end_date = today + timedelta(days=7)

        # Мокування результату - порожній список
        mocked_result = MagicMock()
        mocked_result.scalars().all.return_value = []  # Немає контактів
        self.session.execute.return_value = mocked_result

        # Очікуваний SQL-запит
        stmt = select(Contact).filter(
            and_(
                func.to_char(Contact.birthday, 'MM-DD') >= func.to_char(today,
                                                                        'MM-DD'),
                func.to_char(Contact.birthday, 'MM-DD') <= func.to_char(
                    end_date, 'MM-DD'),
                Contact.user == self.user
            )
        )

        # Виклик функції
        result = await get_upcoming_birthdays(self.session, self.user)

        # Перевірка текстового вигляду SQL-запиту
        actual_query = str(self.session.execute.call_args[0][
                               0])  # Отримуємо запит, переданий у `execute`
        self.assertEqual(actual_query,
                         str(stmt))  # Порівнюємо текстове представлення запитів

        # Перевірки результатів
        self.assertEqual(result, [])  # Має повернути порожній список
        self.session.execute.assert_called_once()  # Перевіряємо, що `execute` викликали

    async def test_get_upcoming_birthdays_db_error(self):
        # Імітація помилки під час виконання запиту
        self.session.execute.side_effect = Exception("Database error")

        with self.assertRaises(Exception) as context:
            await get_upcoming_birthdays(self.session, self.user)

        self.assertIn("Error fetching upcoming birthdays",
                      str(context.exception))  # Перевірка тексту виключення
