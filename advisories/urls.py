from django.urls import path
from . import views

app_name = 'advisories'

urlpatterns = [
    path('', views.advisory_list, name='advisory_list'),
    path('<int:pk>/', views.advisory_detail, name='advisory_detail'),
    path('api/advisories/', views.advisory_api, name='advisory_api'),
]
