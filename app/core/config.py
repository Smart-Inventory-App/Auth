from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql://user:password@localhost:5432/tpp_db"
    JWT_SECRET: str = "change-this-secret-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_EXPIRE_MINUTES: int = 60
    JWT_RESET_EXPIRE_MINUTES: int = 15
    DEBUG: bool = True

    class Config:
        env_file = ".env"


settings = Settings()
