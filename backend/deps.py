"""
Database dependencies and application settings
"""
from sqlmodel import SQLModel, create_engine, Session
from pydantic_settings import BaseSettings
from typing import Generator
import os


class Settings(BaseSettings):
    """Application settings from environment variables"""
    
    # Database
    DATABASE_URL: str = "sqlite:///./iso27001.db"
    DATABASE_ECHO: bool = False
    
    # Default host for scans
    HOST_DEFAULT: str = "yourwebsite.com"
    
    # OpenAI API
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = "gpt-4"
    OPENAI_TEMPERATURE: float = 0.1
    
    # Security scanning
    ENABLE_NPM_AUDIT: bool = True
    ENABLE_SAFETY_CHECK: bool = True
    ENABLE_BANDIT_SCAN: bool = True
    ENABLE_SSL_CHECK: bool = True
    
    # API settings
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "ISO 27001 Agent"
    PROJECT_VERSION: str = "1.0.0"
    
    # CORS
    BACKEND_CORS_ORIGINS: list[str] = [
        "http://localhost:3000",
        "http://localhost:3001", 
        "http://127.0.0.1:3000",
        "http://127.0.0.1:3001"
    ]
    
    # Security
    SECRET_KEY: str = "your-secret-key-change-in-production"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # Reporting
    REPORTS_DIR: str = "./reports"
    
    class Config:
        env_file = ".env"
        case_sensitive = True


# Global settings instance
settings = Settings()

# Database engine
engine = create_engine(
    settings.DATABASE_URL,
    echo=settings.DATABASE_ECHO,
    connect_args={"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {}
)


def init_db() -> None:
    """Initialize database tables"""
    SQLModel.metadata.create_all(engine)


def get_session() -> Generator[Session, None, None]:
    """Get database session dependency"""
    with Session(engine) as session:
        yield session


def get_settings() -> Settings:
    """Get settings dependency"""
    return settings


# Create reports directory
os.makedirs(settings.REPORTS_DIR, exist_ok=True)