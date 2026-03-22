from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.db.models import Count
from django.views.decorators.csrf import csrf_exempt

from .models import CVE, CVEControlMapping
from .services import fetch_cves_from_nvd, process_cves


@login_required
def cve_feed(request):
    """CVE feed page with filtering."""
    severity = request.GET.get('severity', '')
    search = request.GET.get('search', '')

    cves = CVE.objects.filter(cve_id__regex=r'^CVE-202[3-6]') | CVE.objects.filter(cve_id__regex=r'^CVE-202[3-6]')
    cves = cves.order_by('-published_date')

    if severity:
        cves = cves.filter(severity_level=severity.upper())
    if search:
        cves = cves.filter(cve_id__icontains=search) | cves.filter(description__icontains=search)

    # Stats
    severity_stats = CVE.objects.values('severity_level').annotate(count=Count('id'))
    stats_dict = {s['severity_level']: s['count'] for s in severity_stats}

    context = {
        'cves': cves[:100],
        'severity_filter': severity,
        'search_query': search,
        'total_cves': CVE.objects.count(),
        'critical_count': stats_dict.get('CRITICAL', 0),
        'high_count': stats_dict.get('HIGH', 0),
        'medium_count': stats_dict.get('MEDIUM', 0),
        'low_count': stats_dict.get('LOW', 0),
    }
    return render(request, 'cve_engine/cve_feed.html', context)


@login_required
def cve_detail(request, cve_id):
    """Detailed CVE view."""
    cve = get_object_or_404(CVE, cve_id=cve_id)
    mappings = CVEControlMapping.objects.filter(cve=cve)
    advisories = cve.advisories.all()
    alerts = cve.cve_alerts.all()

    context = {
        'cve': cve,
        'mappings': mappings,
        'advisories': advisories,
        'alerts': alerts,
    }
    return render(request, 'cve_engine/cve_detail.html', context)


@login_required
def cve_api_list(request):
    """API endpoint for CVE data."""
    cves = CVE.objects.filter(cve_id__regex=r'^CVE-202[3-6]').order_by('-published_date')[:50]
    data = [{
        'id': c.id,
        'cve_id': c.cve_id,
        'description': c.description[:200],
        'severity_score': c.severity_score,
        'severity_level': c.severity_level,
        'severity_color': c.severity_color,
        'published_date': c.published_date.isoformat(),
        'vendor': c.vendor,
        'product': c.product,
        'latitude': c.latitude,
        'longitude': c.longitude,
        'country': c.country,
    } for c in cves]
    return JsonResponse({'cves': data})


@login_required
def fetch_cves_now(request):
    """Manually trigger CVE fetch."""
    if request.method == 'POST':
        cve_list = fetch_cves_from_nvd()
        count = process_cves(cve_list)
        return JsonResponse({
            'status': 'success',
            'message': f'{count} new CVEs ingested',
            'count': count,
        })
    return JsonResponse({'error': 'POST required'}, status=405)


@login_required
def cve_stats_api(request):
    """API for CVE statistics."""
    severity_stats = CVE.objects.values('severity_level').annotate(count=Count('id'))
    vendor_stats = CVE.objects.exclude(vendor='').values('vendor').annotate(
        count=Count('id')
    ).order_by('-count')[:10]

    return JsonResponse({
        'severity': list(severity_stats),
        'vendors': list(vendor_stats),
        'total': CVE.objects.count(),
    })
