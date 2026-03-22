from django.urls import path
from . import views

app_name = 'darkweb'

urlpatterns = [
    path('', views.darkweb_dashboard, name='dashboard'),
    path('monitors/', views.monitor_list, name='monitor_list'),
    path('monitors/create/', views.monitor_create, name='monitor_create'),
    path('alerts/', views.alert_list, name='alert_list'),
    path('alerts/<int:pk>/', views.alert_detail, name='alert_detail'),
    path('search/', views.live_search, name='live_search'),
    path('api/darkweb-stats/', views.darkweb_stats_api, name='stats_api'),
    path('api/simulate-scan/', views.simulate_scan, name='simulate_scan'),
    path('api/search/', views.darkweb_search_api, name='search_api'),
]
