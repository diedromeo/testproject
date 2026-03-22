from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver


class UserProfile(models.Model):
    """Extended user profile with role separation and onboarding data."""
    ROLE_CHOICES = [
        ('super_admin', 'Super Admin'),
        ('client_admin', 'Client Admin'),
        ('compliance_manager', 'Compliance Manager'),
        ('auditor', 'Auditor'),
        ('vendor_user', 'Vendor User'),
    ]
    INDUSTRY_CHOICES = [
        ('IT', 'IT / SaaS'),
        ('Banking', 'Banking / Fintech'),
        ('Healthcare', 'Healthcare'),
        ('Insurance', 'Insurance'),
        ('Government', 'Government'),
        ('Other', 'Other'),
    ]

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='client_admin')
    organization = models.CharField(max_length=200, blank=True)
    industry = models.CharField(max_length=50, choices=INDUSTRY_CHOICES, blank=True)
    org_size = models.CharField(max_length=50, blank=True)
    country = models.CharField(max_length=100, blank=True)
    
    phone = models.CharField(max_length=20, blank=True)
    avatar_initial = models.CharField(max_length=2, blank=True)
    is_onboarded = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.username} ({self.get_role_display()})"

    @property
    def display_name(self):
        if self.user.first_name:
            return f"{self.user.first_name} {self.user.last_name}".strip()
        return self.user.username

    @property
    def initials(self):
        if self.avatar_initial:
            return self.avatar_initial
        if self.user.first_name and self.user.last_name:
            return f"{self.user.first_name[0]}{self.user.last_name[0]}".upper()
        return self.user.username[:2].upper()

    @property
    def is_admin(self):
        return self.role == 'super_admin' or self.user.is_superuser

    @property
    def is_client(self):
        return self.role in ['client_admin', 'compliance_manager']

    @property
    def is_auditor(self):
        return self.role == 'auditor'


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        role = 'super_admin' if instance.is_superuser else 'client_admin'
        UserProfile.objects.create(user=instance, role=role)


class AuditLog(models.Model):
    """Track all system activities."""
    ACTION_TYPES = [
        ('cve_fetch', 'CVE Fetched'),
        ('advisory_created', 'Advisory Created'),
        ('alert_triggered', 'Alert Triggered'),
        ('vendor_updated', 'Vendor Updated'),
        ('compliance_check', 'Compliance Check'),
        ('user_action', 'User Action'),
        ('darkweb_scan', 'Dark Web Scan'),
    ]

    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    action_type = models.CharField(max_length=50, choices=ACTION_TYPES)
    description = models.TextField()
    metadata = models.JSONField(default=dict, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"[{self.action_type}] {self.description[:50]}"


class SystemConfig(models.Model):
    """System configuration key-value store."""
    key = models.CharField(max_length=100, unique=True)
    value = models.TextField()
    description = models.TextField(blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.key}: {self.value[:50]}"


class DashboardWidget(models.Model):
    """Dashboard widget configuration."""
    WIDGET_TYPES = [
        ('counter', 'Counter'),
        ('chart', 'Chart'),
        ('table', 'Table'),
        ('map', 'Map'),
        ('feed', 'Feed'),
    ]

    name = models.CharField(max_length=100)
    widget_type = models.CharField(max_length=20, choices=WIDGET_TYPES)
    config = models.JSONField(default=dict)
    position = models.IntegerField(default=0)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ['position']

    def __str__(self):
        return self.name
