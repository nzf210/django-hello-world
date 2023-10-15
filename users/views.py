import json
import os
import re
from django.http import JsonResponse
import jwt
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.views import APIView
from rest_framework.decorators import (
    api_view,
)
from rest_framework import status
from .models import User
from .serializers import AuthUserSerializer, AuthUserUpdateSerializer
import hashlib
from .utils.jwt import TokenManager
from .utils.validate_req_jwt import validate_access_token
from .utils.validate_jwt_token import validate_jwt_token
from django.db import IntegrityError
from django.http import HttpResponse


def validate_email(value: str) -> bool:
    pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
    if re.match(pattern, value):
        return False
    else:
        return True


@api_view(["GET"])
def get_users(request):
    if request.method == "GET":
        users = User.objects.all()
        serializer = AuthUserSerializer(users, many=True)
        return JsonResponse(serializer.data, safe=False)


@api_view(["GET", "PATCH", "DELETE"])
@validate_access_token
def get_user(request, pk):
    try:
        user = User.objects.get(pk=pk)
    except User.DoesNotExist:
        return JsonResponse({"error": "Invalid pk"}, status=status.HTTP_404_NOT_FOUND)

    if request.method == "GET":
        serializer = AuthUserSerializer(user)
        return JsonResponse(serializer.data, safe=False)

    if request.method == "PATCH":
        serializer = AuthUserUpdateSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            try:
                if "password" in request.data:
                    password = request.data.get("password")
                    hashed_password = hashlib.sha256(password.encode()).hexdigest()
                    serializer.validated_data["password"] = hashed_password

                serializer.save()
                return JsonResponse(serializer.data, status=status.HTTP_200_OK)

            except IntegrityError:
                return JsonResponse(
                    {"message": "Username or email already exists."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        return JsonResponse(
            {"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST
        )

    if request.method == "DELETE":
        user.delete()
        return JsonResponse(
            {"message": "User deleted"}, status=status.HTTP_204_NO_CONTENT
        )


class RegisterAuthUser(APIView):
    def post(self, request):
        validate_access_token(self)
        try:
            serializer = AuthUserSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        except IntegrityError as e:
            return JsonResponse(
                {"message": f"already exists, error is {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST,
            )


class LoginAuthUser(APIView):
    def post(self, request):
        try:
            username = request.data.get("username")
            password = request.data.get("password")
            user = User.objects.get(username=username)

            if not user or not user.check_password(raw_password=password):
                raise AuthenticationFailed("pengguna atau password salah")
            payload = {"user_id": user.id}
            access_token = TokenManager().generate_token(payload=payload)
            refresh_token = TokenManager().generate_refresh(payload=payload)
            response = Response()
            response.set_cookie(key="access_token", value=access_token, httponly=True)
            response.set_cookie(key="refresh_token", value=refresh_token, httponly=True)
            response.data = {
                "jwt": access_token,
            }

            return response
        except Exception as e:
            return JsonResponse({"message": str(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(["POST"])
@validate_jwt_token
def logout(request):
    try:
        response = JsonResponse({"jwt": ""})
        response.delete_cookie("access_token")
        response.delete_cookie("refresh_token")
        return response
    except Exception as e:
        return JsonResponse({"message": str(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(["GET"])
@validate_access_token
def refresh_jwt(request):
    try:
        token = request.COOKIES.get(
            "refresh_token"
        )  # Get the value of the "refresh_token" cookie
        if not token:
            return JsonResponse(
                {"message": "Please provide a refresh token"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        refresh_jwt = TokenManager().refresh_token(token=token)
        if refresh_jwt:
            refresh_key = os.environ.get("JWT_REFRESH_TOKEN_PRIVATE_KEY")
            decoded_token = jwt.decode(refresh_jwt, refresh_key, algorithms=["HS256"])
            if decoded_token:
                payload = decoded_token.copy()
                del payload["exp"]  # Remove the old expiration time
                del payload["iat"]
                access_token = TokenManager().generate_token(payload=payload)
                if access_token:
                    return JsonResponse(
                        {"jwt": access_token}, status=status.HTTP_200_OK
                    )
                else:
                    return JsonResponse(
                        {"message": "Token expired, please re-authenticate"},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
            else:
                return JsonResponse(
                    {"message": "Token expired, please re-authenticate."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        else:
            return JsonResponse(
                {"message": "Token expired, please re-authenticate."},
                status=status.HTTP_400_BAD_REQUEST,
            )
    except User.DoesNotExist:
        return JsonResponse(
            {"message": "User or password invalid"}, status=status.HTTP_200_OK
        )
