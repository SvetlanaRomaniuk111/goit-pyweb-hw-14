import contextlib
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, \
    async_sessionmaker, create_async_engine
from src.conf.config import config

# Ініціалізація двигуна з використанням DB_URL з конфігураційного файлу
engine: AsyncEngine = create_async_engine(config.DB_URL, echo=True)

# Створення сесії
SessionLocal = async_sessionmaker(autocommit=False, autoflush=False,
                                  bind=engine)


class DatabaseSessionManager:
    def __init__(self, url: str):
        self._engine: AsyncEngine | None = create_async_engine(url)
        self._session_maker: async_sessionmaker = async_sessionmaker(
            autoflush=False, expire_on_commit=False, bind=self._engine)

    @contextlib.asynccontextmanager
    async def session(self):
        if self._session_maker is None:
            raise Exception("Session is not initialized")
        session = self._session_maker()
        try:
            yield session
        except Exception as err:
            print(err)
            await session.rollback()
            raise err
        finally:
            await session.close()


sessionmanager = DatabaseSessionManager(config.DB_URL)


async def get_db():
    async with sessionmanager.session() as session:
        yield session
