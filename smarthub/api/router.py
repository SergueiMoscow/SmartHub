from fastapi import APIRouter

router = APIRouter()

@router.get("/devices")
async def devices():
    return {"message": "Hello World"}
