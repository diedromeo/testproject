from django.contrib import admin
from .models import CVE, CVEControlMapping


@admin.register(CVE)
class CVEAdmin(admin.ModelAdmin):
    list_display = ['cve_id', 'severity_level', 'severity_score', 'vendor', 'product', 'published_date']
    list_filter = ['severity_level', 'vendor']
    search_fields = ['cve_id', 'description', 'vendor', 'product']


@admin.register(CVEControlMapping)
class CVEControlMappingAdmin(admin.ModelAdmin):
    list_display = ['cve', 'control_name', 'framework', 'created_at']
    list_filter = ['framework']
