from fastapi import FastAPI

from app.routers.auth import router as auth_router


app = FastAPI(
    title="FastAPI Authentication API",
    version="1.0.0",
)


# Authentication routes
app.include_router(auth_router)


@app.get("/")
def root():
    return {
        "message": "Authentication API is running"
    }
