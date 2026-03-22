"""Context processors for global template variables."""


def global_context(request):
    """Add global context variables to all templates."""
    from alerts.models import Alert
    from cve_engine.models import CVE
    from advisories.models import Advisory
    from darkweb.models import DarkWebAlert

    unresolved_alerts = 0
    total_cves = 0
    active_advisories = 0
    darkweb_new = 0
    user_role = 'client'

    try:
        unresolved_alerts = Alert.objects.filter(status='open').count()
        total_cves = CVE.objects.count()
        active_advisories = Advisory.objects.filter(is_active=True).count()
        darkweb_new = DarkWebAlert.objects.filter(status='new').count()
    except Exception:
        pass

    if request.user.is_authenticated:
        try:
            user_role = request.user.profile.role
        except Exception:
            user_role = 'admin' if request.user.is_superuser else 'client'

    return {
        'unresolved_alerts_count': unresolved_alerts,
        'total_cves_count': total_cves,
        'active_advisories_count': active_advisories,
        'darkweb_new_count': darkweb_new,
        'user_role': user_role,
        'platform_name': 'ThreatShield',
    }
