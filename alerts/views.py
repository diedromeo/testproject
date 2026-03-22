from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.utils import timezone

from .models import Alert


@login_required
def alert_list(request):
    """List all alerts with filtering."""
    status = request.GET.get('status', '')
    severity = request.GET.get('severity', '')
    alert_type = request.GET.get('type', '')

    alerts = Alert.objects.all()
    if status:
        alerts = alerts.filter(status=status)
    if severity:
        alerts = alerts.filter(severity=severity)
    if alert_type:
        alerts = alerts.filter(alert_type=alert_type)

    context = {
        'alerts': alerts[:100],
        'open_count': Alert.objects.filter(status='open').count(),
        'critical_count': Alert.objects.filter(severity='critical', status='open').count(),
        'total_count': Alert.objects.count(),
        'status_filter': status,
        'severity_filter': severity,
        'type_filter': alert_type,
    }
    return render(request, 'alerts/alert_list.html', context)


@login_required
def alert_detail(request, pk):
    """Alert detail view."""
    alert = get_object_or_404(Alert, pk=pk)
    return render(request, 'alerts/alert_detail.html', {'alert': alert})


@login_required
def resolve_alert(request, pk):
    """Resolve an alert."""
    alert = get_object_or_404(Alert, pk=pk)
    alert.status = 'resolved'
    alert.resolved_at = timezone.now()
    alert.save()
    return redirect('alerts:alert_list')


@login_required
def alert_api(request):
    """API for alerts."""
    alerts = Alert.objects.filter(status='open')[:30]
    data = [{
        'id': a.id,
        'title': a.title,
        'severity': a.severity,
        'status': a.status,
        'alert_type': a.alert_type,
        'created_at': a.created_at.isoformat(),
        'cve_id': a.linked_cve.cve_id if a.linked_cve else None,
    } for a in alerts]
    return JsonResponse({'alerts': data})
