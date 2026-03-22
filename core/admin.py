from django.contrib import admin
from .models import AuditLog, SystemConfig, DashboardWidget, UserProfile


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'role', 'organization', 'created_at']
    list_filter = ['role']


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ['action_type', 'description', 'user', 'created_at']
    list_filter = ['action_type', 'created_at']
    search_fields = ['description']


@admin.register(SystemConfig)
class SystemConfigAdmin(admin.ModelAdmin):
    list_display = ['key', 'value', 'updated_at']


@admin.register(DashboardWidget)
class DashboardWidgetAdmin(admin.ModelAdmin):
    list_display = ['name', 'widget_type', 'position', 'is_active']
