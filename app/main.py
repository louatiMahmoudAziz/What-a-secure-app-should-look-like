from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def read_root():
    return {"app": "steganoAppsec!"}

@app.get("/health")
def health_check():
    return {"status": "healthy"}