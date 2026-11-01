from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST
from .forms import SnapshotImportForm
from .models import Firewall, Rule, Alias, LogicalInterface, Snapshot, AuditEvent
from .opnsense import OPNsenseClient, DeviceError
from .reconcile import plan_for

@login_required
@permission_required("fleet.view_firewall", raise_exception=True)
def dashboard(request):
    devices = []
    for fw in Firewall.objects.all():
        plan = plan_for(fw)
        devices.append({"firewall": fw, "plan": plan,
            "drift": sum(i["status"] in ("missing", "changed", "conflict", "out_of_scope") for i in plan["items"])})
    return render(request, "fleet/dashboard.html", {"devices": devices, "rule_count": Rule.objects.count(),
        "alias_count": Alias.objects.count(), "interface_count": LogicalInterface.objects.count()})

@login_required
@permission_required("fleet.view_firewall", raise_exception=True)
def firewall_detail(request, pk):
    fw = get_object_or_404(Firewall, pk=pk)
    return render(request, "fleet/firewall.html", {"firewall": fw, "plan": plan_for(fw),
        "mappings": fw.interface_mappings.select_related("logical_interface"), "form": SnapshotImportForm()})

@login_required
@permission_required(("fleet.view_firewall", "fleet.refresh_firewall"), raise_exception=True)
@require_POST
def import_snapshot(request, pk):
    fw = get_object_or_404(Firewall, pk=pk)
    form = SnapshotImportForm(request.POST, request.FILES)
    if form.is_valid():
        Snapshot.objects.create(firewall=fw, data=form.cleaned_data["snapshot"], source="import")
        AuditEvent.objects.create(actor=request.user.username, action="snapshot.import", detail=fw.name)
        messages.success(request, "Snapshot imported. Drift report updated.")
        return redirect("firewall", pk=pk)
    return render(request, "fleet/firewall.html", {"firewall": fw, "plan": plan_for(fw),
        "mappings": fw.interface_mappings.select_related("logical_interface"), "form": form}, status=400)

@login_required
@permission_required(("fleet.view_firewall", "fleet.refresh_firewall"), raise_exception=True)
@require_POST
def pull_snapshot(request, pk):
    fw = get_object_or_404(Firewall, pk=pk)
    if not fw.enabled:
        messages.error(request, "Enable this firewall before pulling a snapshot.")
        return redirect("firewall", pk=pk)
    try:
        data = OPNsenseClient(fw).snapshot()
        Snapshot.objects.create(firewall=fw, data=data, source="api")
        AuditEvent.objects.create(actor=request.user.username, action="snapshot.pull", detail=fw.name)
        messages.success(request, "Configuration read from device. No device changes made.")
    except DeviceError as exc:
        messages.error(request, str(exc))
    return redirect("firewall", pk=pk)

@login_required
@permission_required("fleet.view_firewall", raise_exception=True)
def download_plan(request, pk):
    fw = get_object_or_404(Firewall, pk=pk)
    response = JsonResponse(plan_for(fw), json_dumps_params={"indent": 2})
    response["Content-Disposition"] = f'attachment; filename="firewall-{fw.pk}-plan.json"'
    return response


@login_required
def settings_page(request):
    from django.conf import settings
    return render(request, "fleet/settings.html", {"central_login": settings.OIDC_ENABLED})
