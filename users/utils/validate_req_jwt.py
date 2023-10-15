from functools import wraps
import os
import jwt
from rest_framework.exceptions import AuthenticationFailed


def validate_access_token(view_func):
    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        access_token = request.COOKIES.get("access_token")

        if not access_token:
            raise AuthenticationFailed("Access token not found")
        try:
            payload = jwt.decode(
                access_token,
                os.environ.get("JWT_ACCESS_TOKEN_PRIVATE_KEY"),
                algorithms=["HS256"],
            )
            if not payload:
                raise AuthenticationFailed("Invalid token type")
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Access token has expired")
        except jwt.DecodeError:
            raise AuthenticationFailed("Invalid access token")

        return view_func(request, *args, **kwargs)

    return _wrapped
