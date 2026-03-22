from django.urls import path
from . import views

app_name = 'core'

urlpatterns = [
    path('', views.landing_page, name='landing'),
    path('about/', views.about_page, name='about'),
    path('articles/', views.articles_page, name='articles'),
    path('articles/<slug:slug>/', views.article_detail, name='article_detail'),
    path('checklists/', views.checklists, name='checklists'),
    path('contact/', views.contact_page, name='contact'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('integrations/', views.integrations_page, name='integrations'),
    path('roadmap/', views.roadmap_page, name='roadmap'),
    path('login/', views.login_view, name='login'),
    path('login/admin/', views.admin_login_view, name='admin_login'),
    path('login/auditor/', views.auditor_login_view, name='auditor_login'),
    path('login/client/', views.client_login_view, name='client_login'),
    path('logout/', views.logout_view, name='logout'),
    path('register/', views.register_view, name='register'),
    path('register/client/', views.client_register_view, name='client_register'),
    path('onboarding/', views.onboarding_view, name='onboarding'),
    path('api/dashboard-stats/', views.dashboard_stats_api, name='dashboard_stats_api'),
    path('api/activity-feed/', views.activity_feed_api, name='activity_feed_api'),
]
