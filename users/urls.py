from django.urls import path

from . import views as api


urlpatterns = [
    path("", api.get_users, name="get_users"),
    path("<str:pk>/", api.get_user, name="get_user"),
]
