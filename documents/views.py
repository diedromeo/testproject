from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
import hashlib
import ollama
from .models import Document
from compliance.models import ComplianceControl
from core.models import AuditLog

@login_required
def document_list(request):
    documents = Document.objects.all().order_by('-uploaded_at')
    # Provide stats
    total_docs = documents.count()
    needs_review = documents.filter(status='pending').count()
    
    from .models import ComplianceRequirement
    requirements = []
    selected_framework = request.GET.get('framework', '')
    
    if selected_framework:
        requirements = ComplianceRequirement.objects.filter(framework_type=selected_framework)
        # If no requirements in DB, seed some for demo
        if not requirements.exists():
            seed_requirements(selected_framework)
            requirements = ComplianceRequirement.objects.filter(framework_type=selected_framework)

    return render(request, 'documents/document_list.html', {
        'documents': documents,
        'total_docs': total_docs,
        'needs_review': needs_review,
        'requirements': requirements,
        'selected_framework': selected_framework,
        'frameworks': ComplianceRequirement.FRAMEWORK_TYPES
    })


def seed_requirements(fw):
    from .models import ComplianceRequirement
    if fw == 'SOC2':
        reqs = [
            ('Information Security Policy', 'General overview of security posture'),
            ('Access Control Policy', 'Rules for provisioning and revoking access'),
            ('Risk Assessment Report', 'Annual risk analysis and mitigation plan'),
            ('Incident Response Plan', 'Procedures for handling security events'),
            ('Network Diagram', 'Current architectural overview of the systems'),
        ]
    elif fw == 'ISO27001':
        reqs = [
            ('Statement of Applicability (SoA)', 'List of controls selected and excluded'),
            ('ISMS Scope Document', 'Defined boundary of the ISMS'),
            ('Internal Audit Report', 'Results of the most recent internal audit'),
            ('Management Review Minutes', 'Evidence of management oversight'),
            ('Asset Register', 'Inventory of all hardware, software, and data'),
        ]
    else:
        reqs = [
            ('General Security Policy', 'Standard organizational security rules'),
            ('Compliance Evidence 1', 'Sample evidence for core controls'),
            ('External Audit Report', 'Last 3rd party validation'),
        ]
    
    for name, desc in reqs:
        ComplianceRequirement.objects.get_or_create(
            framework_type=fw,
            name=name,
            description=desc,
            is_mandatory=True
        )

@login_required
def document_upload(request):
    if request.method == 'POST':
        title = request.POST.get('title')
        doc_type = request.POST.get('document_type')
        upload_file = request.FILES.get('file')
        control_ids = request.POST.getlist('controls')
        
        if title and doc_type and upload_file:
            # Hash calculation
            file_content = upload_file.read()
            file_hash = hashlib.sha256(file_content).hexdigest()
            upload_file.seek(0)
            
            # Authenticity / Duplicate check
            is_authentic = not Document.objects.filter(file_hash=file_hash).exists()
            
            # Generate AI Summary using Ollama
            ai_summary = ""
            try:
                # Basic context since binary extraction can be tricky
                prompt = f"You are a compliance AI. Analyze this context and provide a strictly 2-sentence professional compliance summary for a document uploaded to our system. Document Title: '{title}'. Document Type: '{doc_type}'. Context: This is a secure audit evidence upload."
                response = ollama.chat(model='llama3', messages=[{'role': 'user', 'content': prompt}])
                ai_summary = response['message']['content'].strip()
            except Exception as e:
                ai_summary = "AI Summary generation failed or Ollama not running."

            doc = Document.objects.create(
                title=title,
                document_type=doc_type,
                file=upload_file,
                uploaded_by=request.user,
                file_hash=file_hash,
                is_authentic=is_authentic,
                ai_summary=ai_summary
            )
            
            if control_ids:
                controls = ComplianceControl.objects.filter(id__in=control_ids)
                doc.controls.set(controls)
                
            AuditLog.objects.create(
                user=request.user,
                action_type='user_action',
                description=f"Uploaded document: {title} (Hash: {file_hash[:8]})"
            )
            return redirect('documents:document_list')

    controls = ComplianceControl.objects.filter(framework__is_active=True)
    return render(request, 'documents/document_upload.html', {
        'controls': controls
    })
