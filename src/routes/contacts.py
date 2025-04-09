from fastapi_limiter.depends import RateLimiter
from fastapi import APIRouter, Query, Path, HTTPException, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession
from src.database.db import get_db
from src.entity.models import User
from src.repository import contacts as repositories_contacts
from src.schemas.contact import (
    ContactCreateSchema,
    ContactResponse,
    ContactUpdateSchema,
    ContactShortResponse,
)
from src.services.auth import auth_service
from src.conf import messages

router = APIRouter(prefix="/contacts", tags=["contacts"])


@router.get("/", response_model=list[ContactResponse])
async def get_contacts(
    limit: int = Query(10, ge=10, le=500),
    offset: int = Query(0, ge=0),
    first_name: str = Query(None),
    last_name: str = Query(None),
    email: str = Query(None),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(auth_service.get_current_user),
):
    """
    Retrieves a list of contacts.

    :param limit: int: The maximum number of contacts to return (default: 10, min: 10, max: 500).
    :param offset: int: The offset from which to start returning contacts (default: 0, min: 0).
    :param first_name: str: Optional filter by first name.
    :param last_name: str: Optional filter by last name.
    :param email: str: Optional filter by email.
    :param db: AsyncSession: The database session.
    :param user: User: The current user.
    :return: list[ContactResponse]: A list of contact responses.
    :notes: This endpoint returns a paginated list of contacts, with optional filtering by first name, last name, and email.
    """
    contacts = await repositories_contacts.get_contacts(
        limit, offset, first_name, last_name, email, db, user
    )
    return contacts


@router.get("/birthdays", response_model=list[ContactShortResponse])
async def get_upcoming_birthdays(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(auth_service.get_current_user),
):
    """
    Retrieves a list of upcoming birthdays.

    :param db: AsyncSession: The database session.
    :param user: User: The current user.
    :return: list[ContactShortResponse]: A list of contact short responses with upcoming birthdays.
    :raises HTTPException: If an error occurs while retrieving birthdays.
    :notes: This endpoint returns a list of contacts with upcoming birthdays, validated against the ContactShortResponse model.
    """
    try:
        contacts = await repositories_contacts.get_upcoming_birthdays(db, user)
        validated_contacts = [
            ContactShortResponse.model_validate(contact) for contact in contacts
        ]
        return validated_contacts
    except HTTPException as http_exc:
        raise http_exc
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=messages.INTERNAL_SERVER_ERROR,
        )


@router.post(
    "/",
    response_model=ContactResponse,
    description="No more than 1 request in 20 seconds",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RateLimiter(times=1, seconds=20))],
)
async def create_contact(
    body: ContactCreateSchema,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(auth_service.get_current_user),
):
    """
    Creates a new contact.

    :param body: ContactCreateSchema: The contact creation schema.
    :param db: AsyncSession: The database session.
    :param user: User: The current user.
    :return: ContactResponse: The created contact response.
    :raises HTTPException: If an error occurs while creating the contact.
    :notes: This endpoint is rate-limited to 1 request per 20 seconds.
            The contact creation schema is validated against the ContactCreateSchema model.
    """
    try:
        contact = await repositories_contacts.create_contact(body, db, user)
        return contact
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=messages.INTERNAL_SERVER_ERROR,
        )


@router.get("/{contact_id}", response_model=ContactResponse)
async def get_contact(
    contact_id: int = Path(ge=1),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(auth_service.get_current_user),
):
    """
    Retrieves a contact by ID.

    :param contact_id: int: The ID of the contact to retrieve (must be greater than or equal to 1).
    :param db: AsyncSession: The database session.
    :param user: User: The current user.
    :return: ContactResponse: The retrieved contact response.
    :raises HTTPException: If the contact is not found.
    :notes: This endpoint retrieves a contact by its ID, and returns a ContactResponse object.
            If the contact is not found, a 404 error is raised.
    """
    contact = await repositories_contacts.get_contact(contact_id, db, user)
    if contact is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=messages.CONTACT_NOT_FOUND
        )
    return contact


@router.put("/{contact_id}")
async def update_contact(
    body: ContactUpdateSchema,
    contact_id: int = Path(ge=1),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(auth_service.get_current_user),
):
    """
    Updates a contact by ID.

    :param body: ContactUpdateSchema: The contact update schema.
    :param contact_id: int: The ID of the contact to update (must be greater than or equal to 1).
    :param db: AsyncSession: The database session.
    :param user: User: The current user.
    :return: Contact: The updated contact.
    :raises HTTPException: If the contact is not found.
    :notes: This endpoint updates a contact by its ID, using the provided update schema.
            If the contact is not found, a 404 error is raised.
            The contact update schema is validated against the ContactUpdateSchema model.
    """
    contact = await repositories_contacts.update_contact(contact_id, body, db, user)
    if contact is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=messages.CONTACT_NOT_FOUND
        )
    return contact


@router.delete("/{contact_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_contact(
    contact_id: int = Path(ge=1),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(auth_service.get_current_user),
):
    """
    Deletes a contact by ID.

    :param contact_id: int: The ID of the contact to delete (must be greater than or equal to 1).
    :param db: AsyncSession: The database session.
    :param user: User: The current user.
    :return: None: No content is returned (204 status code).
    :notes: This endpoint deletes a contact by its ID.
            If the contact is deleted successfully, a 204 status code is returned.
    """
    contact = await repositories_contacts.delete_contact(contact_id, db, user)
    return contact
