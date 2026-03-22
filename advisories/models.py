from django.db import models


class Advisory(models.Model):
    """CERT-IN style security advisory."""
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    SOURCE_CHOICES = [
        ('CERT-IN', 'CERT-IN'),
        ('AUTO', 'Auto-Generated'),
        ('MANUAL', 'Manual'),
    ]

    title = models.CharField(max_length=500)
    description = models.TextField()
    affected_systems = models.TextField(blank=True)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='medium')
    recommended_action = models.TextField()
    source = models.CharField(max_length=20, choices=SOURCE_CHOICES, default='AUTO')
    linked_cve = models.ForeignKey(
        'cve_engine.CVE', on_delete=models.SET_NULL, null=True, blank=True, related_name='advisories'
    )
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name_plural = 'Advisories'

    def __str__(self):
        return self.title[:80]

    @property
    def severity_color(self):
        colors = {
            'low': '#4ade80',
            'medium': '#fbbf24',
            'high': '#f97316',
            'critical': '#ef4444',
        }
        return colors.get(self.severity, '#6b7280')

    @property
    def severity_icon(self):
        icons = {
            'low': '🟢',
            'medium': '🟡',
            'high': '🟠',
            'critical': '🔴',
        }
        return icons.get(self.severity, '⚪')
