import os
from pymongo import MongoClient
from mongoengine import connect
from dotenv import load_dotenv
from urllib.parse import quote_plus

load_dotenv()

db_name = os.environ.get("MONGO_DB")
user = os.environ.get("MONGO_USER")
password = os.environ.get("MONGO_PASSWORD")
mongo_host = os.environ.get("MONGO_HOST", "localhost")
mongo_port = os.environ.get("MONGO_PORT", "27017")  # now configurable

# encoded_user = quote_plus(user)
# encoded_password = quote_plus(password)

#uri = f"mongodb://{encoded_user}:{encoded_password}@{mongo_host}:{mongo_port}/{db_name}?authSource=admin"
uri = f"mongodb://localhost:27017/"
client = MongoClient(uri)
connect(
    db=db_name,
    host=uri
)

db = client[db_name]
