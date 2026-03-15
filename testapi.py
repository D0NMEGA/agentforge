from fastapi import APIRouter
try:
    router = APIRouter(description="hello")
    print("SUCCESS")
except Exception as e:
    print("ERROR:", e)
