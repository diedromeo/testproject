from django.urls import path
from . import views

app_name = 'threat_viz'

urlpatterns = [
    path('map/', views.threat_map, name='threat_map'),
    path('globe/', views.threat_globe, name='threat_globe'),
    path('api/geo-data/', views.geo_data_api, name='geo_data_api'),
    path('api/globe-data/', views.globe_data_api, name='globe_data_api'),
]
