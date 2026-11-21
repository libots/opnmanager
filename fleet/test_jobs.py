import copy
from unittest.mock import Mock

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase

from .deployment import deployment_plan
from .jobs import enqueue, recover_interrupted, run_pending
from .models import DeviceJob, Firewall, InterfaceMapping, LogicalInterface, Rule, Snapshot
from .opnsense import DeviceError

EMPTY = {"schema_version": 1, "rules": [], "aliases": [], "interfaces": [], "groups": [], "categories": []}


class DeviceJobTests(TestCase):
    def setUp(self):
        self.fw = Firewall.objects.create(name="Test", base_url="https://fw.test", credential_prefix="TEST")
        logical = LogicalInterface.objects.create(name="LAN")
        InterfaceMapping.objects.create(firewall=self.fw, logical_interface=logical, device_interface="lan")
        Snapshot.objects.create(firewall=self.fw, data=copy.deepcopy(EMPTY))
        self.rule = Rule.objects.create(name="First", interface=logical, sequence=100)
        self.user = get_user_model().objects.create_superuser("admin-test", password="Test-only-password")
        self.client.force_login(self.user)

    def device(self):
        plan = deployment_plan(self.fw)
        payload = plan["rows"][0]["operation"]["payload"]
        client = Mock(ROLLBACK_SECONDS=60)
        client.savepoint.return_value = "1.1"
        client.snapshot.side_effect = [copy.deepcopy(EMPTY), {**EMPTY, "rules": [{**payload, "uuid": "r"}]}]
        return plan, client

    def test_deploy_post_only_enqueues_and_worker_runs_it(self):
        plan, client = self.device()
        response = self.client.post(
            f"/firewalls/{self.fw.pk}/deploy/",
            {"acknowledge": "yes", "approval_sha256": plan["approval_sha256"], "selected_rules": [str(self.rule.pk)]},
        )
        job = DeviceJob.objects.get()
        self.assertRedirects(response, f"/jobs/{job.pk}/")
        self.assertEqual(job.status, DeviceJob.QUEUED)
        client.savepoint.assert_not_called()
        page = self.client.get(f"/jobs/{job.pk}/")
        self.assertContains(page, 'http-equiv="refresh"')
        run_pending(client_factory=lambda fw: client)
        job.refresh_from_db()
        self.assertEqual(job.status, DeviceJob.SUCCEEDED, job.message)
        self.assertIn("Applied and verified 1", job.message)
        self.assertIsNotNone(job.finished_at)
        page = self.client.get(f"/jobs/{job.pk}/")
        self.assertNotContains(page, 'http-equiv="refresh"')
        self.assertContains(page, "Applied and verified 1")

    def test_unacknowledged_deploy_is_rejected_without_a_job(self):
        response = self.client.post(f"/firewalls/{self.fw.pk}/deploy/", {"selected_rules": [str(self.rule.pk)]})
        self.assertRedirects(response, f"/firewalls/{self.fw.pk}/deploy/")
        self.assertFalse(DeviceJob.objects.exists())

    def test_definition_sync_post_enqueues(self):
        response = self.client.post(f"/firewalls/{self.fw.pk}/sync/", {"approval_sha256": "x"})
        job = DeviceJob.objects.get()
        self.assertRedirects(response, f"/jobs/{job.pk}/")
        self.assertEqual(job.kind, DeviceJob.DEFINITIONS_SYNC)
        run_pending(client_factory=lambda fw: Mock())
        job.refresh_from_db()
        self.assertEqual(job.status, DeviceJob.FAILED)
        self.assertIn("Plan changed", job.message)

    def test_duplicate_active_job_is_refused(self):
        enqueue(self.fw, DeviceJob.RULES_DEPLOY, {}, "test")
        with self.assertRaisesMessage(DeviceError, "already queued or running"):
            enqueue(self.fw, DeviceJob.RULES_DEPLOY, {}, "test")

    def test_device_and_unexpected_errors_fail_the_job_without_stopping_the_queue(self):
        first = enqueue(self.fw, DeviceJob.RULES_DEPLOY, {"approval_sha256": "stale"}, "test")
        second = enqueue(self.fw, DeviceJob.DEFINITIONS_SYNC, {"approval_sha256": "x"}, "test")

        def factory(fw):
            if DeviceJob.objects.get(status=DeviceJob.RUNNING).pk == second.pk:
                raise RuntimeError("boom")
            return Mock()

        with self.assertLogs("fleet.jobs", "ERROR"):
            run_pending(client_factory=factory)
        first.refresh_from_db()
        second.refresh_from_db()
        self.assertEqual((first.status, second.status), (DeviceJob.FAILED, DeviceJob.FAILED))
        self.assertIn("Rule plan changed", first.message)
        self.assertIn("Unexpected internal error", second.message)
        self.assertNotIn("boom", second.message)

    def test_worker_start_marks_orphaned_running_jobs_interrupted(self):
        job = enqueue(self.fw, DeviceJob.RULES_DEPLOY, {}, "test")
        DeviceJob.objects.filter(pk=job.pk).update(status=DeviceJob.RUNNING)
        self.assertEqual(recover_interrupted(), 1)
        job.refresh_from_db()
        self.assertEqual(job.status, DeviceJob.INTERRUPTED)
        self.assertIn("rolled back automatically", job.message)

    def test_run_jobs_once_command(self):
        enqueue(self.fw, DeviceJob.RULES_DEPLOY, {"approval_sha256": "stale"}, "test")
        call_command("run_jobs", "--once", stdout=Mock(), stderr=Mock())
        self.assertEqual(DeviceJob.objects.get().status, DeviceJob.FAILED)

    def test_job_page_requires_permission(self):
        job = enqueue(self.fw, DeviceJob.RULES_DEPLOY, {}, "test")
        self.client.force_login(get_user_model().objects.create_user("basic"))
        self.assertEqual(self.client.get(f"/jobs/{job.pk}/").status_code, 403)
