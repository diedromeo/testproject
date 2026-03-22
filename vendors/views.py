from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse

from .models import Vendor, VendorAssessment


@login_required
def vendor_list(request):
    """List all vendors."""
    risk_level = request.GET.get('risk', '')
    vendors = Vendor.objects.all()
    if risk_level:
        vendors = vendors.filter(risk_level=risk_level)

    context = {
        'vendors': vendors,
        'total_vendors': Vendor.objects.count(),
        'high_risk': Vendor.objects.filter(risk_score__gte=7.0).count(),
    }
    return render(request, 'vendors/vendor_list.html', context)


@login_required
def vendor_detail(request, pk):
    """Vendor detail view."""
    vendor = get_object_or_404(Vendor, pk=pk)
    assessments = vendor.assessments.all()[:5]
    context = {
        'vendor': vendor,
        'assessments': assessments,
    }
    return render(request, 'vendors/vendor_detail.html', context)


@login_required
def vendor_api(request):
    """API for vendor data."""
    vendors = Vendor.objects.all()
    data = [{
        'id': v.id,
        'name': v.name,
        'risk_score': v.risk_score,
        'risk_level': v.risk_level,
        'risk_color': v.risk_color,
        'category': v.category,
        'country': v.country,
    } for v in vendors]
    return JsonResponse({'vendors': data})
