"""Background execution of device writes.

Web requests only validate input and enqueue a DeviceJob; the `run_jobs`
worker process claims jobs one at a time and runs them. A deploy therefore
survives a reverse-proxy timeout or a closed browser tab, and a Gunicorn
restart can't cut it off halfway. Workflows keep their own approval checks
and the shared per-firewall write lock.
"""

import logging

from django.db import transaction
from django.utils import timezone

from .models import AuditEvent, DeviceJob, Rule
from .opnsense import DeviceError, OPNsenseClient

log = logging.getLogger(__name__)

INTERRUPTED_MESSAGE = (
    "The job worker stopped while this job was running. Any rules applied but not yet confirmed are "
    "rolled back automatically by OPNsense; definition changes may be partial. Pull a fresh snapshot and "
    "review again."
)


def _deploy_rules(job, client):
    from .deployment import execute_deployment

    count = execute_deployment(
        job.firewall,
        job.params.get("approval_sha256"),
        [value for value in job.params.get("selected_rules", []) if value],
        client,
        job.actor,
        accept_warnings=bool(job.params.get("accept_warnings")),
        allow_unprotected=bool(job.params.get("allow_unprotected")),
    )
    return f"Applied and verified {count} selected rule changes."


def _sync_definitions(job, client):
    from .definition_sync import execute_definition_plan

    rule_id = job.params.get("rule_id")
    rule = Rule.objects.filter(pk=rule_id).first() if rule_id else None
    if rule_id and rule is None:
        raise DeviceError("The rule this synchronization was for no longer exists.")
    count = execute_definition_plan(
        job.firewall,
        job.params.get("approval_sha256"),
        client,
        job.actor,
        rule=rule,
        remove=[value for value in job.params.get("remove_aliases", []) if value],
    )
    return f"Verified {count} supporting-definition changes. No manager rules were deployed."


HANDLERS = {DeviceJob.RULES_DEPLOY: _deploy_rules, DeviceJob.DEFINITIONS_SYNC: _sync_definitions}


def enqueue(firewall, kind, params, actor):
    if kind not in HANDLERS:
        raise ValueError(f"Unknown job kind {kind}")
    with transaction.atomic():
        if DeviceJob.objects.filter(firewall=firewall, kind=kind, status__in=DeviceJob.ACTIVE).exists():
            raise DeviceError("A job of this kind is already queued or running for this firewall.")
        job = DeviceJob.objects.create(firewall=firewall, kind=kind, params=params, actor=actor)
    AuditEvent.objects.create(actor=actor, action="job.queued", detail=f"{firewall.name} {kind} #{job.pk}")
    return job


def claim_next():
    """Atomically move the oldest queued job to running; safe with more than one worker."""
    for job in DeviceJob.objects.filter(status=DeviceJob.QUEUED).order_by("created_at", "pk")[:5]:
        claimed = DeviceJob.objects.filter(pk=job.pk, status=DeviceJob.QUEUED).update(
            status=DeviceJob.RUNNING, started_at=timezone.now()
        )
        if claimed:
            return DeviceJob.objects.select_related("firewall").get(pk=job.pk)
    return None


def run_job(job, client_factory=OPNsenseClient):
    try:
        message = HANDLERS[job.kind](job, client_factory(job.firewall))
        status = DeviceJob.SUCCEEDED
    except DeviceError as exc:
        message, status = str(exc), DeviceJob.FAILED
    except Exception:
        log.exception("Device job %s failed unexpectedly", job.pk)
        message = "Unexpected internal error; see the server log. Pull a fresh snapshot before retrying."
        status = DeviceJob.FAILED
    job.status, job.message, job.finished_at = status, message, timezone.now()
    job.save(update_fields=["status", "message", "finished_at"])
    return job


def recover_interrupted():
    """Mark jobs left running by a stopped worker. Call once when a worker starts."""
    return DeviceJob.objects.filter(status=DeviceJob.RUNNING).update(
        status=DeviceJob.INTERRUPTED, message=INTERRUPTED_MESSAGE, finished_at=timezone.now()
    )


def run_pending(client_factory=OPNsenseClient):
    """Drain the queue in this process. Used by the worker loop and by tests."""
    ran = []
    while job := claim_next():
        ran.append(run_job(job, client_factory))
    return ran
