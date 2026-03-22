from django.db import models


class ComplianceFramework(models.Model):
    """Compliance frameworks (ISO, GDPR, DPDP, SOC2, HIPAA, PCI DSS)."""
    FRAMEWORK_TYPES = [
        ('ISO27001', 'ISO 27001'),
        ('GDPR', 'GDPR'),
        ('DPDP', 'DPDP Act (India)'),
        ('SOC2', 'SOC 2'),
        ('HIPAA', 'HIPAA'),
        ('PCIDSS', 'PCI DSS'),
        ('RBI', 'RBI Guidelines'),
        ('NPCI', 'NPCI Standards'),
        ('UIDAI', 'UIDAI/Aadhaar'),
        ('SEBI', 'SEBI Regulations'),
        ('IRDAI', 'IRDAI Guidelines'),
    ]

    name = models.CharField(max_length=200)
    framework_type = models.CharField(max_length=20, choices=FRAMEWORK_TYPES)
    description = models.TextField()
    version = models.CharField(max_length=50, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.name

    @property
    def compliance_percentage(self):
        total = self.controls.count()
        if total == 0:
            return 0
        compliant = self.controls.filter(status='compliant').count()
        return round((compliant / total) * 100)


class ComplianceControl(models.Model):
    """Individual compliance controls within a framework."""
    STATUS_CHOICES = [
        ('compliant', 'Compliant'),
        ('non_compliant', 'Non-Compliant'),
        ('partial', 'Partially Compliant'),
        ('not_assessed', 'Not Assessed'),
    ]

    framework = models.ForeignKey(ComplianceFramework, on_delete=models.CASCADE, related_name='controls')
    control_id = models.CharField(max_length=50)
    title = models.CharField(max_length=300)
    description = models.TextField()
    category = models.CharField(max_length=200, blank=True)
    status = models.CharField(max_length=15, choices=STATUS_CHOICES, default='not_assessed')
    mandatory = models.BooleanField(default=True)
    compliance_body = models.CharField(max_length=200, blank=True)
    evidence = models.TextField(blank=True)
    last_audit_date = models.DateTimeField(null=True, blank=True)
    next_audit_date = models.DateTimeField(null=True, blank=True)
    auditor_notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['control_id']

    def __str__(self):
        return f"{self.control_id}: {self.title[:50]}"


class AuditRecord(models.Model):
    """Audit records for compliance validation."""
    STATUS_CHOICES = [
        ('scheduled', 'Scheduled'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]

    framework = models.ForeignKey(ComplianceFramework, on_delete=models.CASCADE, related_name='audits')
    auditor_name = models.CharField(max_length=200)
    audit_type = models.CharField(max_length=100)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='scheduled')
    findings = models.TextField(blank=True)
    recommendations = models.TextField(blank=True)
    score = models.FloatField(null=True, blank=True)
    audit_date = models.DateTimeField()
    completed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-audit_date']

    def __str__(self):
        return f"Audit: {self.framework.name} by {self.auditor_name}"
