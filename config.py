import os
from dotenv import load_dotenv

load_dotenv()

class Config:

    SECRET_KEY = os.getenv("SECRET_KEY", "ChangeThisSecretKey")

    SQLALCHEMY_DATABASE_URI = (
        f"mssql+pyodbc://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}"
        f"@{os.getenv('DB_SERVER')}/{os.getenv('DB_NAME')}"
        "?driver=ODBC+Driver+18+for+SQL+Server"
        "&TrustServerCertificate=yes"
    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False