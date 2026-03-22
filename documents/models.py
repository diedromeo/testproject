from django.db import models
from django.contrib.auth.models import User
from compliance.models import ComplianceControl

class Document(models.Model):
    DOC_TYPES = [
        ('policy', 'Policy Document'),
        ('sop', 'Standard Operating Procedure (SOP)'),
        ('evidence', 'Audit Evidence'),
        ('checklist', 'Compliance Checklist'),
        ('report', 'Audit Report'),
        ('vendor_assessment', 'Vendor Risk Assessment'),
        ('incident_log', 'Incident Response Log'),
        ('contract', 'Legal Contract / Agreement'),
        ('diagram', 'Architecture Diagram'),
        ('other', 'Other Document'),
    ]

    title = models.CharField(max_length=200)
    document_type = models.CharField(max_length=20, choices=DOC_TYPES)
    file = models.FileField(upload_to='documents/')
    uploaded_by = models.ForeignKey(User, on_delete=models.CASCADE)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    controls = models.ManyToManyField(ComplianceControl, related_name='documents', blank=True)
    status = models.CharField(max_length=20, choices=[('pending', 'Pending Review'), ('approved', 'Approved'), ('rejected', 'Rejected')], default='pending')
    
    file_hash = models.CharField(max_length=64, blank=True)
    ai_summary = models.TextField(blank=True)
    is_authentic = models.BooleanField(default=True)
    
    
    def __str__(self):
        return self.title


class ComplianceRequirement(models.Model):
    """Specific document requirements for various compliance frameworks."""
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
    framework_type = models.CharField(max_length=20, choices=FRAMEWORK_TYPES)
    name = models.CharField(max_length=200)
    description = models.TextField()
    is_mandatory = models.BooleanField(default=True)
    suggested_filename = models.CharField(max_length=255, blank=True)
    
    def __str__(self):
        return f"{self.framework_type} - {self.name}"

    @property
    def is_fulfilled(self):
        """Check if any document of this type exists for the user."""
        # For simplicity, we match by name or type in this demo
        return Document.objects.filter(title__icontains=self.name).exists()
