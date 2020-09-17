from django.urls import path
from . import views


urlpatterns = [
    path('register_host', views.register_host, name='register_host'),
    path('add_events', views.add_events, name='add_events'),
]
