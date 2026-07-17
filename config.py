import os

from dotenv import load_dotenv

load_dotenv(override=True)

class Config:

    SECRET_KEY = os.getenv("SECRET_KEY", "ChangeThisSecretKey")

    SQLALCHEMY_DATABASE_URI = os.getenv("SQLALCHEMY_DATABASE_URI")

    SQLALCHEMY_TRACK_MODIFICATIONS = False
