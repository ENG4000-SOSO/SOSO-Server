from fastapi import HTTPException, status
import jwt
import os
import time


def create_jwt(data: dict, secret_key: str, lifespan_in_seconds: int):
    '''
    Creates a JWT given a payload and lifespan.

    Parameters
    ----------
    `data` The payload to be put into the JWT.

    `lifespan_in_seconds` The token lifespan in seconds.

    Returns
    -------
    The encoded JWT.
    '''
    # Copy payload data
    payload = data.copy()

    # Calculate expiry time based on the current time and the token lifespan
    expire = time.time() + lifespan_in_seconds

    # Add expiry to the payload
    payload.update({ 'exp': expire })

    # Encode the token
    return jwt.encode(
        payload,
        secret_key,
        algorithm=os.environ['JWT_HASHING_ALGORITHM']
    )


def create_access_jwt(data: dict):
    '''
    Creates an access JWT given a payload.

    Access JWTs are short-lived. Their lifespan will be calculated from an
    environment variable.

    Parameters
    ----------
    `data` The payload to be put into the access JWT.

    Returns
    -------
    The encoded access JWT.
    '''
    return create_jwt(
        data,
        os.environ['ACCESS_SECRET_KEY'],
        int(os.environ['ACCESS_JWT_LIFESPAN_SECONDS'])
    )


def create_refresh_jwt(data: dict):
    '''
    Creates a refresh JWT given a payload.

    Refresh JWTs are used to renew access JWTs.

    Refresh JWTs are long-lived. Their lifespan will be calculated from an
    environment variable.

    Parameters
    ----------
    `data` The payload to be put into the refresh JWT.

    Returns
    -------
    The encoded refresh JWT.
    '''
    return create_jwt(
        data,
        os.environ['REFRESH_SECRET_KEY'],
        int(os.environ['REFRESH_JWT_LIFESPAN_SECONDS'])
    )


def decode_and_verify_jwt(token: str, secret_key: str):
    '''
    Decodes a verifies a JWT.

    The decoded payload of the token is returned if verification succeeds,
    otherwise and exception is raised.

    Parameters
    ----------
    `token` The JWT to be decoded and verified.

    `secret_key` The secret key to use when verifying the JWT.

    Returns
    -------
    The decoded payload of the token (if verification is successful).

    Raises
    ------
    `HTTPException`
        - 401 Unauthorized if the token has expired.
        - 401 Unauthorized if the token is invalid.
    '''
    try:
        return jwt.decode(
            token,
            secret_key,
            algorithms=[os.environ['JWT_HASHING_ALGORITHM']]
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Token has expired',
            headers={'WWW-Authenticate': 'Bearer'}
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid token',
            headers={'WWW-Authenticate': 'Bearer'}
        )


def decode_and_verify_access_jwt(token: str):
    '''
    Decodes a verifies an access JWT.

    The decoded payload of the access token is returned if verification
    succeeds, otherwise and exception is raised.

    Parameters
    ----------
    `token` The access JWT to be decoded and verified.

    Returns
    -------
    The decoded payload of the access token (if verification is successful).

    Raises
    ------
    `HTTPException`
        - 401 Unauthorized if the token has expired.
        - 401 Unauthorized if the token is invalid.
    '''
    return decode_and_verify_jwt(token, os.environ['ACCESS_SECRET_KEY'])


def decode_and_verify_refresh_jwt(token: str):
    '''
    Decodes a verifies an refresh JWT.

    The decoded payload of the refresh token is returned if verification
    succeeds, otherwise and exception is raised.

    Parameters
    ----------
    `token` The refresh JWT to be decoded and verified.

    Returns
    -------
    The decoded payload of the refresh token (if verification is successful).

    Raises
    ------
    `HTTPException`
        - 401 Unauthorized if the token has expired.
        - 401 Unauthorized if the token is invalid.
    '''
    return decode_and_verify_jwt(token, os.environ['REFRESH_SECRET_KEY'])


def refresh_jwt(refresh_jwt: str):
    '''
    Refreshes a JWT token.

    Given a refresh token, a new access token will be generated.

    Parameters
    ----------
    `refresh_jwt` The refresh token to be used to generate a new access token.
    '''
    try:
        payload = decode_and_verify_jwt(
            refresh_jwt,
            os.environ['REFRESH_SECRET_KEY']
        )
        return create_refresh_jwt(payload.user)
    except HTTPException:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid refresh token',
            headers={'WWW-Authenticate': 'Bearer'}
        )
