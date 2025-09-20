from sqlmodel import SQLModel, create_engine, Sessionfrom sqlmodel import SQLModel, create_engine, Session""""""

from pydantic_settings import BaseSettings

from typing import Generatorfrom pydantic_settings import BaseSettings

import os

Database initialization and settings for ISO 27001 AgentDatabase dependencies and application settings

class Settings(BaseSettings):

    """Application settings with enterprise defaults"""class Settings(BaseSettings):

    

    # Database    DATABASE_URL: str = "sqlite:///./iso.db"""""""

    DATABASE_URL: str = "sqlite:///./iso27001_enterprise.db"

    DATABASE_ECHO: bool = False    HOST_DEFAULT: str = "yourwebsite.com"

    

    # Security    OPENAI_API_KEY: str = ""from sqlmodel import SQLModel, create_engine, Session

    SECRET_KEY: str = "your-secret-key-change-in-production"

    ALGORITHM: str = "HS256"

    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    settings = Settings()from sqlmodel import SQLModel, create_engine, Sessionfrom pydantic_settings import BaseSettings

    # OpenAI for LangChain

    OPENAI_API_KEY: str = ""engine = create_engine(settings.DATABASE_URL, connect_args={"check_same_thread": False})

    OPENAI_MODEL: str = "gpt-4"

    from pydantic_settings import BaseSettingsfrom typing import Generator

    # Authentication

    GOOGLE_CLIENT_ID: str = ""def init_db():

    GOOGLE_CLIENT_SECRET: str = ""

        SQLModel.metadata.create_all(engine)import os

    # Storage (for evidence)

    EVIDENCE_STORAGE_PATH: str = "./evidence"

    AWS_S3_BUCKET: str = ""

    AWS_ACCESS_KEY_ID: str = ""def get_session():class Settings(BaseSettings):

    AWS_SECRET_ACCESS_KEY: str = ""

        return Session(engine)

    # Application    DATABASE_URL: str = "sqlite:///./iso.db"

    APP_NAME: str = "ISO 27001 Enterprise Agent"

    APP_VERSION: str = "1.0.0"    HOST_DEFAULT: str = "yourwebsite.com"class Settings(BaseSettings):

    DEBUG: bool = False

    HOST_DEFAULT: str = "yourcompany.com"    OPENAI_API_KEY: str = ""    """Application settings from environment variables"""

    

    # Email (for notifications)        

    SMTP_HOST: str = ""

    SMTP_PORT: int = 587    class Config:    # Database

    SMTP_USER: str = ""

    SMTP_PASSWORD: str = ""        env_file = ".env"    DATABASE_URL: str = "sqlite:///./iso27001.db"

    

    # External integrations    DATABASE_ECHO: bool = False

    SLACK_WEBHOOK_URL: str = ""

    JIRA_URL: str = ""settings = Settings()    

    JIRA_USERNAME: str = ""

    JIRA_TOKEN: str = ""engine = create_engine(settings.DATABASE_URL, connect_args={"check_same_thread": False})    # Default host for scans

    

    # Compliance defaults    HOST_DEFAULT: str = "yourwebsite.com"

    DEFAULT_RISK_APPETITE: int = 15

    EVIDENCE_RETENTION_YEARS: int = 7def init_db():    

    CAPA_DEFAULT_SLA_DAYS: int = 30

        SQLModel.metadata.create_all(engine)    # OpenAI API

    class Config:

        env_file = ".env"    OPENAI_API_KEY: str = ""



# Initialize settingsdef get_session():    OPENAI_MODEL: str = "gpt-4"

settings = Settings()

    return Session(engine)    OPENAI_TEMPERATURE: float = 0.1

# Database setup    

engine = create_engine(    # Security scanning

    settings.DATABASE_URL,    ENABLE_NPM_AUDIT: bool = True

    echo=settings.DATABASE_ECHO,    ENABLE_SAFETY_CHECK: bool = True

    connect_args={"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {}    ENABLE_BANDIT_SCAN: bool = True

)    ENABLE_SSL_CHECK: bool = True

    

def init_db() -> None:    # API settings

    """Initialize database tables"""    API_V1_STR: str = "/api/v1"

    SQLModel.metadata.create_all(engine)    PROJECT_NAME: str = "ISO 27001 Agent"

    PROJECT_VERSION: str = "1.0.0"

def get_session() -> Generator[Session, None, None]:    

    """Dependency for database sessions"""    # CORS

    with Session(engine) as session:    BACKEND_CORS_ORIGINS: list[str] = [

        yield session        "http://localhost:3000",

        "http://localhost:3001", 

def create_db_and_tables():        "http://127.0.0.1:3000",

    """Create database and tables - used in startup"""        "http://127.0.0.1:3001"

    SQLModel.metadata.create_all(engine)    ]

    

# Ensure evidence storage directory exists    # Security

os.makedirs(settings.EVIDENCE_STORAGE_PATH, exist_ok=True)    SECRET_KEY: str = "your-secret-key-change-in-production"
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