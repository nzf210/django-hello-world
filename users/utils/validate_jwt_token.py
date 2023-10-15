import os
import jwt
from functools import wraps
from django.http.response import JsonResponse
from rest_framework import status


def validate_jwt_token(func):
    @wraps(func)
    def wrapper(request, *args, **kwargs):
        token = request.headers.get("Authorization")
        if not token:
            return JsonResponse(
                {"message": "Invalid token"}, status=status.HTTP_403_FORBIDDEN
            )
        split_token = token.split(" ")[1]
        secret_key = os.environ.get("JWT_ACCESS_TOKEN_PRIVATE_KEY")
        try:
            jwt.decode(split_token, secret_key, algorithms=["HS256"])
        except jwt.InvalidTokenError:
            response = JsonResponse({"jwt": ""})
            response.delete_cookie("access_token")
            response.delete_cookie("refresh_token")
            return JsonResponse(
                {"message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED
            )
        except Exception as e:
            response = JsonResponse({"jwt": ""})
            response.delete_cookie("access_token")
            response.delete_cookie("refresh_token")
            return JsonResponse(
                {"message": f"Error {str(e)}"}, status=status.HTTP_401_UNAUTHORIZED
            )
        return func(request, *args, **kwargs)

    return wrapper
