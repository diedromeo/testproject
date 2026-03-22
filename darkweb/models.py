from django.db import models


class DarkWebMonitor(models.Model):
    """Dark web monitoring configuration for an organization."""
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('paused', 'Paused'),
        ('expired', 'Expired'),
    ]

    organization_name = models.CharField(max_length=200)
    domains = models.JSONField(default=list, help_text='List of domains to monitor')
    keywords = models.JSONField(default=list, help_text='Keywords to watch for')
    emails = models.JSONField(default=list, help_text='Email addresses to monitor')
    api_key = models.CharField(max_length=500, blank=True, help_text='API key for dark web service')
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='active')
    last_scan = models.DateTimeField(null=True, blank=True)
    scan_frequency_hours = models.IntegerField(default=24)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-updated_at']

    def __str__(self):
        return f"Monitor: {self.organization_name}"


class DarkWebAlert(models.Model):
    """Alerts from dark web monitoring scans."""
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    TYPE_CHOICES = [
        ('credential_leak', 'Credential Leak'),
        ('data_breach', 'Data Breach'),
        ('mention', 'Organization Mention'),
        ('paste', 'Paste Site Detection'),
        ('market', 'Dark Market Listing'),
        ('ransomware', 'Ransomware Group'),
    ]
    STATUS_CHOICES = [
        ('new', 'New'),
        ('investigating', 'Investigating'),
        ('confirmed', 'Confirmed'),
        ('false_positive', 'False Positive'),
        ('resolved', 'Resolved'),
    ]

    monitor = models.ForeignKey(DarkWebMonitor, on_delete=models.CASCADE, related_name='alerts')
    title = models.CharField(max_length=500)
    description = models.TextField()
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='medium')
    alert_type = models.CharField(max_length=20, choices=TYPE_CHOICES, default='mention')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='new')
    source = models.CharField(max_length=200, blank=True)
    raw_data = models.JSONField(default=dict, blank=True)
    affected_assets = models.TextField(blank=True)
    remediation = models.TextField(blank=True)
    discovered_at = models.DateTimeField(auto_now_add=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-discovered_at']

    def __str__(self):
        return f"[{self.severity.upper()}] {self.title[:60]}"

    @property
    def severity_color(self):
        colors = {
            'low': '#22c55e',
            'medium': '#f59e0b',
            'high': '#f97316',
            'critical': '#ef4444',
        }
        return colors.get(self.severity, '#6b7280')


class DarkWebScanResult(models.Model):
    """Individual scan results/findings."""
    monitor = models.ForeignKey(DarkWebMonitor, on_delete=models.CASCADE, related_name='scan_results')
    scan_date = models.DateTimeField(auto_now_add=True)
    findings_count = models.IntegerField(default=0)
    credentials_found = models.IntegerField(default=0)
    mentions_found = models.IntegerField(default=0)
    pastes_found = models.IntegerField(default=0)
    summary = models.TextField(blank=True)
    raw_response = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ['-scan_date']

    def __str__(self):
        return f"Scan: {self.monitor.organization_name} ({self.scan_date.strftime('%Y-%m-%d')})"
