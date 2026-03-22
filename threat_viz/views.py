import random
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse

from cve_engine.models import CVE


@login_required
def threat_map(request):
    """Leaflet map showing CVE locations."""
    return render(request, 'threat_viz/threat_map.html')


@login_required
def threat_globe(request):
    """3D globe showing threat data."""
    return render(request, 'threat_viz/threat_globe.html')


@login_required
def geo_data_api(request):
    """API for map geo data."""
    cves = CVE.objects.exclude(latitude__isnull=True).exclude(longitude__isnull=True)[:100]
    markers = [{
        'cve_id': c.cve_id,
        'description': c.description[:150],
        'severity': c.severity_level,
        'severity_color': c.severity_color,
        'score': c.severity_score,
        'lat': c.latitude,
        'lng': c.longitude,
        'country': c.country,
        'vendor': c.vendor,
        'product': c.product,
    } for c in cves]
    return JsonResponse({'markers': markers})


@login_required
def globe_data_api(request):
    """API for 3D globe data with attack arcs."""
    cves = CVE.objects.exclude(latitude__isnull=True)[:50]

    # Create points for each CVE location
    points = []
    for c in cves:
        points.append({
            'lat': c.latitude,
            'lng': c.longitude,
            'severity': c.severity_level,
            'color': c.severity_color,
            'label': c.cve_id,
            'size': c.severity_score / 10.0,
            'country': c.country,
        })

    # Generate attack arcs (simulate attacks between locations)
    arcs = []
    cve_list = list(cves)
    for i in range(min(len(cve_list), 20)):
        src = cve_list[i]
        # Random target (simulating attack path)
        targets = [
            {'lat': 28.6139, 'lng': 77.2090, 'name': 'New Delhi'},
            {'lat': 19.0760, 'lng': 72.8777, 'name': 'Mumbai'},
            {'lat': 12.9716, 'lng': 77.5946, 'name': 'Bangalore'},
            {'lat': 1.3521, 'lng': 103.8198, 'name': 'Singapore'},
            {'lat': 51.5074, 'lng': -0.1278, 'name': 'London'},
            {'lat': 40.7128, 'lng': -74.0060, 'name': 'New York'},
            {'lat': 35.6762, 'lng': 139.6503, 'name': 'Tokyo'},
        ]
        target = random.choice(targets)
        arcs.append({
            'startLat': src.latitude,
            'startLng': src.longitude,
            'endLat': target['lat'],
            'endLng': target['lng'],
            'color': src.severity_color,
            'label': f"{src.cve_id} → {target['name']}",
        })

    # Country heat data
    country_stats = {}
    for c in cves:
        if c.country:
            if c.country not in country_stats:
                country_stats[c.country] = 0
            country_stats[c.country] += c.severity_score

    countries = [{'country': k, 'intensity': v} for k, v in country_stats.items()]

    return JsonResponse({
        'points': points,
        'arcs': arcs,
        'countries': countries,
    })
