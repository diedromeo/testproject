from django.contrib import admin
from .models import Advisory


@admin.register(Advisory)
class AdvisoryAdmin(admin.ModelAdmin):
    list_display = ['title', 'severity', 'source', 'is_active', 'created_at']
    list_filter = ['severity', 'source', 'is_active']
    search_fields = ['title', 'description']
