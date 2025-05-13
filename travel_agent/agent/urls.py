from django.urls import path
from . import views


urlpatterns = [
    path('', views.home, name='home'),
    path('login/', views.login, name='login'),
    path('register/', views.register, name='register'),
    path('logout/', views.logout, name='logout'),


    path('feed/', views.feed, name="feed"),

    path('api/chat/stream/', views.agentic_chat, name='agentic_chat'),
]