import signal
import time

from django.core.management.base import BaseCommand

from fleet.jobs import claim_next, recover_interrupted, run_job


class Command(BaseCommand):
    help = "Run queued device jobs (rule deploys, definition syncs). Run exactly one worker per data directory."

    def add_arguments(self, parser):
        parser.add_argument("--once", action="store_true", help="Drain the queue once and exit.")
        parser.add_argument("--interval", type=float, default=1.0, help="Seconds between queue checks.")

    def handle(self, *args, **options):
        stopping = False

        def stop(signum, frame):
            nonlocal stopping
            stopping = True  # finish the current job, then exit

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        recovered = recover_interrupted()
        if recovered:
            self.stderr.write(f"Marked {recovered} job(s) left running by a previous worker as interrupted.")
        self.stdout.write("Job worker started.")
        while not stopping:
            job = claim_next()
            if job:
                job = run_job(job)
                self.stdout.write(f"Job #{job.pk} {job.kind} on {job.firewall}: {job.status}")
                continue
            if options["once"]:
                break
            time.sleep(options["interval"])
        self.stdout.write("Job worker stopped.")
