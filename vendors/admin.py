from django.contrib import admin
from .models import Vendor, VendorAssessment


@admin.register(Vendor)
class VendorAdmin(admin.ModelAdmin):
    list_display = ['name', 'risk_score', 'risk_level', 'category', 'is_active']
    list_filter = ['risk_level', 'is_active']
    search_fields = ['name', 'category']


@admin.register(VendorAssessment)
class VendorAssessmentAdmin(admin.ModelAdmin):
    list_display = ['vendor', 'assessor', 'score', 'assessment_date']
