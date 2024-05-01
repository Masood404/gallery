from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy import Column, Integer, String, SmallInteger, Index, ForeignKey, DateTime, Text
from sqlalchemy.orm import DeclarativeBase, relationship
from datetime import datetime

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)
migrate = Migrate(db=db)

# All the database models

class User(Base):
    """User model to store in the database"""
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String, unique=True, nullable=False)
    hash = Column(String, nullable=False)
    role_id = Column(SmallInteger, nullable=False, default=3)

    emails = relationship("Email", back_populates="user", cascade="all, delete-orphan")
    images = relationship("Image", back_populates="user", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_username",  "username"),
    )

class Email(Base):
    """Email model to store in the database"""
    __tablename__ = "emails"
    id = Column(Integer, primary_key=True, autoincrement=True)
    email_address = Column(String, nullable=False, unique=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    user = relationship("User", back_populates="emails")

    __table_args__ = (
        Index("idx_email", "email_address"),
    )   

class Metadata(Base):
    """Key Value pair of some metadata such as if the first admin is register, etc."""
    __tablename__ = "metadatas"
    key = Column(String, primary_key=True)
    value = Column(String)

class Image(Base):
    """Image model to store in the database"""
    __tablename__ = "images"

    id = Column(Integer, primary_key=True)
    title = Column(String(100), nullable=False, default="Untitled")
    filename = Column(String, nullable=False, unique=True) # Unique because of filesystems
    upload_date = Column(DateTime, default=datetime.now())
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    user = relationship("User", back_populates="images")