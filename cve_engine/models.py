from django.db import models


class CVE(models.Model):
    """Common Vulnerabilities and Exposures."""
    SEVERITY_CHOICES = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]

    cve_id = models.CharField(max_length=30, unique=True, db_index=True)
    description = models.TextField()
    severity_score = models.FloatField(default=0.0)
    severity_level = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='LOW')
    published_date = models.DateTimeField()
    last_modified = models.DateTimeField(auto_now=True)

    # Additional fields
    vendor = models.CharField(max_length=200, blank=True, default='')
    product = models.CharField(max_length=200, blank=True, default='')
    attack_vector = models.CharField(max_length=50, blank=True, default='')
    attack_complexity = models.CharField(max_length=20, blank=True, default='')
    references = models.JSONField(default=list, blank=True)

    # Geolocation for map
    latitude = models.FloatField(null=True, blank=True)
    longitude = models.FloatField(null=True, blank=True)
    country = models.CharField(max_length=100, blank=True, default='')

    class Meta:
        ordering = ['-published_date']
        verbose_name = 'CVE'
        verbose_name_plural = 'CVEs'

    def __str__(self):
        return f"{self.cve_id} ({self.severity_level})"

    @property
    def severity_color(self):
        colors = {
            'LOW': '#4ade80',
            'MEDIUM': '#fbbf24',
            'HIGH': '#f97316',
            'CRITICAL': '#ef4444',
        }
        return colors.get(self.severity_level, '#6b7280')

    @staticmethod
    def calculate_severity_level(score):
        if score >= 9.0:
            return 'CRITICAL'
        elif score >= 7.0:
            return 'HIGH'
        elif score >= 4.0:
            return 'MEDIUM'
        else:
            return 'LOW'


class CVEControlMapping(models.Model):
    """Maps CVEs to compliance controls."""
    cve = models.ForeignKey(CVE, on_delete=models.CASCADE, related_name='control_mappings')
    control_name = models.CharField(max_length=200)
    framework = models.CharField(max_length=100)
    risk_description = models.TextField()
    mitigation = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.cve.cve_id} → {self.control_name}"
