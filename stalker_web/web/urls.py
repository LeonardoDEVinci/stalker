from django.urls import path
from . import views


urlpatterns = [
    path('search_events', views.searchEvents, name='search_events'),
    path('search', views.searchPage, name='search_page'),
    path('process_events_table', views.processEventsTable, name='process_events_table'),
    path('process/<str:guid>', views.process, name='process'),
    path('manage', views.manage, name='manage'),
    path('downloads', views.downloads, name='downloads'),
    path('logout', views.logout_view, name='logout_url'),
    path('', views.login_view, name='login_url'),
]
