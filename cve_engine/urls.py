from django.urls import path
from . import views

app_name = 'cve_engine'

urlpatterns = [
    path('feed/', views.cve_feed, name='cve_feed'),
    path('detail/<str:cve_id>/', views.cve_detail, name='cve_detail'),
    path('api/cves/', views.cve_api_list, name='cve_api_list'),
    path('api/fetch-now/', views.fetch_cves_now, name='fetch_cves_now'),
    path('api/cve-stats/', views.cve_stats_api, name='cve_stats_api'),
]
