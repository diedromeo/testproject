from django.contrib import admin
from .models import Alert


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ['title', 'severity', 'status', 'alert_type', 'created_at']
    list_filter = ['severity', 'status', 'alert_type']
    search_fields = ['title', 'description']
