from fastapi import FastAPI
from app.security import build_middleware
from app.config import get_settings

app = FastAPI()
settings = get_settings()

# Each 'middleware' returned by build_middleware should be an object with:
# - 'cls': the middleware class to add (e.g., CORSMiddleware)
# - 'options': a dict of keyword arguments for the middleware class
for middleware in build_middleware(settings.app_env, settings.cors_allow_origins):
    app.add_middleware(middleware.cls, **middleware.kwargs)



@app.get("/")
def read_root():
    return {"app": "steganoAppsec!"}

@app.get("/health")
def health_check():
    return {"status": "healthy"}