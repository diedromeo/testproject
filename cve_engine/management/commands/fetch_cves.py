"""
Management command to fetch CVEs periodically.
Can be run as: python manage.py fetch_cves
Or scheduled via cron/Windows Task Scheduler.
"""
import time
from django.core.management.base import BaseCommand
from django.conf import settings

from cve_engine.services import fetch_cves_from_nvd, process_cves


class Command(BaseCommand):
    help = 'Fetch latest CVEs from NVD API (or mock data) and process them'

    def add_arguments(self, parser):
        parser.add_argument(
            '--loop',
            action='store_true',
            help='Run continuously with interval from settings',
        )
        parser.add_argument(
            '--interval',
            type=int,
            default=settings.CVE_FETCH_INTERVAL_MINUTES,
            help='Interval in minutes between fetches (default: 5)',
        )

    def handle(self, *args, **options):
        loop = options['loop']
        interval = options['interval'] * 60  # Convert to seconds

        self.stdout.write(self.style.SUCCESS('🚀 CVE Fetch Engine Started'))

        if loop:
            self.stdout.write(f'Running in loop mode (every {options["interval"]} minutes)')
            while True:
                self._fetch_and_process()
                self.stdout.write(f'Sleeping for {options["interval"]} minutes...')
                time.sleep(interval)
        else:
            self._fetch_and_process()

    def _fetch_and_process(self):
        self.stdout.write('Fetching CVEs...')
        cve_list = fetch_cves_from_nvd()
        self.stdout.write(f'Retrieved {len(cve_list)} CVEs')

        count = process_cves(cve_list)
        self.stdout.write(self.style.SUCCESS(f'✅ Processed {count} new CVEs'))
