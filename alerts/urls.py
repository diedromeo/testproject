from django.urls import path
from . import views

app_name = 'alerts'

urlpatterns = [
    path('', views.alert_list, name='alert_list'),
    path('<int:pk>/', views.alert_detail, name='alert_detail'),
    path('<int:pk>/resolve/', views.resolve_alert, name='resolve_alert'),
    path('api/alerts/', views.alert_api, name='alert_api'),
]
