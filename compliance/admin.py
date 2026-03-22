from django.contrib import admin
from .models import ComplianceFramework, ComplianceControl, AuditRecord


@admin.register(ComplianceFramework)
class ComplianceFrameworkAdmin(admin.ModelAdmin):
    list_display = ['name', 'framework_type', 'is_active', 'created_at']
    list_filter = ['framework_type', 'is_active']


@admin.register(ComplianceControl)
class ComplianceControlAdmin(admin.ModelAdmin):
    list_display = ['control_id', 'title', 'framework', 'status']
    list_filter = ['framework', 'status']
    search_fields = ['control_id', 'title']


@admin.register(AuditRecord)
class AuditRecordAdmin(admin.ModelAdmin):
    list_display = ['framework', 'auditor_name', 'status', 'audit_date']
    list_filter = ['status', 'framework']
