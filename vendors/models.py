from django.db import models


class Vendor(models.Model):
    """Vendor/third-party risk management."""
    RISK_LEVELS = [
        ('low', 'Low Risk'),
        ('medium', 'Medium Risk'),
        ('high', 'High Risk'),
        ('critical', 'Critical Risk'),
    ]

    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    category = models.CharField(max_length=100, blank=True)
    tech_stack = models.JSONField(default=list, blank=True, help_text='Technologies used by vendor')
    risk_score = models.FloatField(default=0.0)
    risk_level = models.CharField(max_length=10, choices=RISK_LEVELS, default='low')
    contact_email = models.EmailField(blank=True)
    website = models.URLField(blank=True)
    country = models.CharField(max_length=100, blank=True)
    compliance_status = models.JSONField(default=dict, blank=True)
    last_assessment_date = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-risk_score']

    def __str__(self):
        return f"{self.name} (Risk: {self.risk_score})"

    @property
    def risk_color(self):
        if self.risk_score >= 8.0:
            return '#ef4444'
        elif self.risk_score >= 6.0:
            return '#f97316'
        elif self.risk_score >= 4.0:
            return '#fbbf24'
        return '#4ade80'

    def update_risk_from_cve(self, cve):
        """Increase risk score if CVE affects vendor tech stack."""
        tech_lower = [t.lower() for t in self.tech_stack]
        vendor_lower = cve.vendor.lower() if cve.vendor else ''
        product_lower = cve.product.lower() if cve.product else ''

        if vendor_lower in self.name.lower() or \
           any(t in vendor_lower or t in product_lower for t in tech_lower):
            increase = cve.severity_score * 0.1
            self.risk_score = min(10.0, self.risk_score + increase)
            self.risk_level = self._calc_risk_level()
            self.save()
            return True
        return False

    def _calc_risk_level(self):
        if self.risk_score >= 8.0:
            return 'critical'
        elif self.risk_score >= 6.0:
            return 'high'
        elif self.risk_score >= 4.0:
            return 'medium'
        return 'low'


class VendorAssessment(models.Model):
    """Vendor security assessments."""
    vendor = models.ForeignKey(Vendor, on_delete=models.CASCADE, related_name='assessments')
    assessor = models.CharField(max_length=200)
    score = models.FloatField()
    findings = models.TextField(blank=True)
    recommendations = models.TextField(blank=True)
    assessment_date = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-assessment_date']

    def __str__(self):
        return f"Assessment: {self.vendor.name} ({self.score})"
