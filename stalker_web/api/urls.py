from django.urls import path
from . import views


urlpatterns = [
    path('test', views.apiTest, name='api_test'),
    path('add_events', views.add_events, name='add_events'),
]
