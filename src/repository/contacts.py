from sqlalchemy import select, and_, extract, func
from sqlalchemy.ext.asyncio import AsyncSession
from src.entity.models import Contact, User
from src.schemas.contact import ContactCreateSchema, ContactUpdateSchema
from datetime import date, timedelta


async def get_contacts(limit: int, offset: int, first_name: str, last_name: str,
                       email: str, db: AsyncSession, user: User):
    """
    Retrieve contacts based on given parameters.

    :param limit: int: The maximum number of contacts to retrieve.
    :param offset: int: The number of contacts to skip.
    :param first_name: str: The first name of the contact to filter by.
    :param last_name: str: The last name of the contact to filter by.
    :param email: str: The email address of the contact to filter by.
    :param db: AsyncSession: The database session.
    :param user: User: The current user.
    :return: list: A list of contacts that match the given parameters. If no contacts are found, an empty list is returned.
    """
    stmt = select(Contact).filter_by(user=user).offset(offset).limit(limit)
    if first_name or last_name or email:
        stmt = stmt.filter(
            and_(
                first_name is None or Contact.first_name.ilike(
                    f"%{first_name}%"),
                last_name is None or Contact.last_name.ilike(f"%{last_name}%"),
                email is None or Contact.email.ilike(f"%{email}%"),
            )
        )
    contacts = await db.execute(stmt)
    return contacts.scalars().all()


async def get_contact(contact_id: int, db: AsyncSession, user: User):
    """
    Retrieve a contact by its ID.

    :param contact_id: int: The ID of the contact to retrieve.
    :param db: AsyncSession: The database session.
    :param user: User: The current user.
    :return: Contact: The contact object if found, otherwise None.
    """
    stmt = select(Contact).filter_by(id=contact_id, user=user)
    contact = await db.execute(stmt)
    return contact.scalar_one_or_none()


async def create_contact(body: ContactCreateSchema, db: AsyncSession,
                         user: User):
    """
    Create a new contact.

    :param body: ContactCreateSchema: The contact data to create.
    :param db: AsyncSession: The database session.
    :param user: User: The current user.
    :return: Contact: The created contact object.
    """
    contact = Contact(**body.model_dump(exclude_unset=True), user=user)
    db.add(contact)
    await db.commit()
    await db.refresh(contact)
    return contact


async def update_contact(contact_id: int, body: ContactUpdateSchema,
                         db: AsyncSession, user: User):
    """
    Update an existing contact.

    :param contact_id: int: The ID of the contact to update.
    :param body: ContactUpdateSchema: The contact data to update.
    :param db: AsyncSession: The database session.
    :param user: User: The current user.
    :return: Contact: The updated contact object. If the contact is not found, None is returned.
    """
    stmt = select(Contact).filter_by(id=contact_id, user=user)
    result = await db.execute(stmt)
    contact = result.scalar_one_or_none()
    if contact:
        for key, value in body.model_dump(exclude_unset=True).items():
            setattr(contact, key, value)
        await db.commit()
        await db.refresh(contact)
    return contact


async def delete_contact(contact_id: int, db: AsyncSession, user: User):
    """
    Delete a contact by its ID.

    :param contact_id: int: The ID of the contact to delete.
    :param db: AsyncSession: The database session.
    :param user: User: The current user.
    :return: Contact: The deleted contact object. If the contact is not found, None is returned.
    """
    stmt = select(Contact).filter_by(id=contact_id, user=user)
    contact = await db.execute(stmt)
    contact = contact.scalar_one_or_none()
    if contact:
        await db.delete(contact)
        await db.commit()
    return contact


async def get_upcoming_birthdays(db: AsyncSession, user: User):
    """
    Fetch contacts who have upcoming birthdays within the next 7 days.

    :param db: AsyncSession: The database session.
    :param user: User: The current user.
    :return: list: A list of contacts who have upcoming birthdays. If no contacts are found, an empty list is returned.
    """
    try:
        today = date.today()
        end_date = today + timedelta(days=7)

        # Обробка дат у форматі MM-DD для врахування місяця та дня
        stmt = select(Contact).filter(
            and_(
                func.to_char(Contact.birthday, 'MM-DD') >= func.to_char(today,
                                                                        'MM-DD'),
                func.to_char(Contact.birthday, 'MM-DD') <= func.to_char(
                    end_date, 'MM-DD'),
                Contact.user == user  # Додаємо фільтр для перевірки користувача
            )
        )
        result = await db.execute(stmt)
        contacts = result.scalars().all()
        return contacts
    except Exception as e:
        raise Exception(f"Error fetching upcoming birthdays: {e}")
