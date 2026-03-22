from django.db import models


class Alert(models.Model):
    """Security alerts triggered by CVEs, vendor issues, or compliance violations."""
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    STATUS_CHOICES = [
        ('open', 'Open'),
        ('investigating', 'Investigating'),
        ('resolved', 'Resolved'),
        ('dismissed', 'Dismissed'),
    ]
    TYPE_CHOICES = [
        ('cve', 'CVE Alert'),
        ('vendor', 'Vendor Risk'),
        ('compliance', 'Compliance'),
        ('breach', 'Breach Alert'),
        ('system', 'System Alert'),
    ]

    title = models.CharField(max_length=500)
    description = models.TextField()
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='medium')
    status = models.CharField(max_length=15, choices=STATUS_CHOICES, default='open')
    alert_type = models.CharField(max_length=15, choices=TYPE_CHOICES, default='system')
    linked_cve = models.ForeignKey(
        'cve_engine.CVE', on_delete=models.SET_NULL, null=True, blank=True, related_name='cve_alerts'
    )
    assigned_to = models.ForeignKey(
        'auth.User', on_delete=models.SET_NULL, null=True, blank=True
    )
    resolved_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"[{self.severity.upper()}] {self.title[:60]}"

    @property
    def severity_color(self):
        colors = {
            'low': '#4ade80',
            'medium': '#fbbf24',
            'high': '#f97316',
            'critical': '#ef4444',
        }
        return colors.get(self.severity, '#6b7280')
