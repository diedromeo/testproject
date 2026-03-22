from django.contrib import admin
from .models import DarkWebMonitor, DarkWebAlert, DarkWebScanResult


@admin.register(DarkWebMonitor)
class DarkWebMonitorAdmin(admin.ModelAdmin):
    list_display = ['organization_name', 'status', 'last_scan', 'created_at']
    list_filter = ['status']


@admin.register(DarkWebAlert)
class DarkWebAlertAdmin(admin.ModelAdmin):
    list_display = ['title', 'severity', 'alert_type', 'status', 'discovered_at']
    list_filter = ['severity', 'alert_type', 'status']
    search_fields = ['title', 'description']


@admin.register(DarkWebScanResult)
class DarkWebScanResultAdmin(admin.ModelAdmin):
    list_display = ['monitor', 'findings_count', 'scan_date']
