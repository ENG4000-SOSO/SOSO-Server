from fastapi import APIRouter
import json
from fastapi.encoders import jsonable_encoder
from helpers.jwt_helper import create_access_jwt, create_refresh_jwt, refresh_jwt
from models.jwt_model import LoginResponse, RefreshJWTRequest, RefreshJWTResponse
import logging
from fastapi import HTTPException
from app_config import get_db_session


logger = logging.getLogger(__name__)
router = APIRouter()


@router.post('/register')
async def register_user():
    refresh_jwt = create_refresh_jwt({ 'user': 'username' })
    access_jwt = create_access_jwt({ 'user': 'username' })
    return jsonable_encoder(LoginResponse(access=access_jwt,refresh=refresh_jwt))


@router.post('/login')
async def login_user():
    refresh_jwt = create_refresh_jwt({ 'user': 'username' })
    access_jwt = create_access_jwt({ 'user': 'username' })
    return jsonable_encoder(LoginResponse(access=access_jwt,refresh=refresh_jwt))


@router.post('/refresh')
async def register_user(refresh_jwt_request: RefreshJWTRequest):
    refresh_token = refresh_jwt_request.token
    new_access_token = refresh_jwt(refresh_token)
    return jsonable_encoder(RefreshJWTResponse(access=new_access_token))
