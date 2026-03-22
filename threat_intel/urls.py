"""URL configuration for threat_intel project."""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin-panel/', admin.site.urls),
    path('', include('core.urls')),
    path('compliance/', include('compliance.urls')),
    path('documents/', include('documents.urls')),
    path('cve/', include('cve_engine.urls')),
    path('advisories/', include('advisories.urls')),
    path('alerts/', include('alerts.urls')),
    path('vendors/', include('vendors.urls')),
    path('ai/', include('ai_assistant.urls')),
    path('threat-viz/', include('threat_viz.urls')),
    path('darkweb/', include('darkweb.urls')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
