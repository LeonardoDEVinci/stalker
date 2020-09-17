from django.urls import path
from . import views


urlpatterns = [
    path('create_mapping', views.createMapping, name='create_mapping'),
    path('search_events', views.searchEvents, name='search_events'),
    path('search', views.searchPage, name='search_page'),
    path('process_events_table', views.processEventsTable, name='process_events_table'),
    path('process/<uuid:guid>', views.process, name='process'),
]
