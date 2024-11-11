from fastapi import Request, Depends, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.security import HTTPBearer
from starlette.responses import Response, JSONResponse
from typing import Callable, Awaitable
import jwt
from helpers.jwt_helper import decode_and_verify_access_jwt


class JWTAuthorizationMiddleware(BaseHTTPMiddleware):

    # These routes should not be protected by JWT authorization (they need to be
    # accessible to any user)
    UNPROTECTED_ROUTES = ['/auth/login', '/auth/register', '/auth/refresh']

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        # Only apply if route is protected
        if not any(request.url.path.startswith(route) for route in self.UNPROTECTED_ROUTES):
            try:
                # Get Authorization header
                authorization_header = request.headers.get('Authorization')

                # Make sure Authorization header is formatted correctly
                if not authorization_header or not authorization_header.startswith('Bearer '):
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail='Missing or invalid Authorization header for protected route',
                        headers={'WWW-Authenticate': 'Bearer'}
                    )

                # Get token from Authorization header
                token = authorization_header.split(' ')[1]

                # Decode the token and verify that it is valid.
                # This method call will throw an error if the token is invalid.
                payload = decode_and_verify_access_jwt(token)

                # Attach decoded token to request
                request.state.user = payload
            except HTTPException as e:
                # If we got an HTTP exception when processing the token, then
                # convert it to a JSON response
                return JSONResponse(
                    status_code=e.status_code,
                    headers=e.headers,
                    content={ 'detail': e.detail }
                )

        # Proceed with the request
        return await call_next(request)
