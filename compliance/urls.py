from django.urls import path
from . import views

app_name = 'compliance'

urlpatterns = [
    path('', views.framework_list, name='framework_list'),
    path('audits/', views.audit_list, name='audit_list'),
    path('controls/', views.controls_list, name='controls_list'),
    path('auditor-dashboard/', views.auditor_dashboard, name='auditor_dashboard'),
    path('<int:pk>/', views.framework_detail, name='framework_detail'),
    path('api/compliance-stats/', views.compliance_stats_api, name='compliance_stats_api'),
]
