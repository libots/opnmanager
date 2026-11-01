"""Explicit selected-rule upsert/apply. No automatic deletion or rollback."""
import difflib
import json
from .alias_sync import digest
from .models import Rule, Snapshot, AuditEvent
from .opnsense import DeviceError
from .reconcile import plan_for, canonical
from .dependencies import rule_definitions


def fingerprint(data):
    return digest({key: sorted(value, key=lambda row: json.dumps(row, sort_keys=True)) if isinstance(value,list) else value for key,value in data.items()})


def deployment_plan(firewall):
    snapshot=firewall.snapshots.first()
    result={'firewall':firewall.name,'snapshot_id':snapshot.pk if snapshot else None,'rows':[]}
    for rule in Rule.objects.all():
        if not rule.applies_to(firewall): continue
        plan=plan_for(firewall,rule_ids={str(rule.pk)},definition_names=rule_definitions(rule))
        errors=list(plan['errors'])
        dependencies=[op for op in plan['operations'] if op['kind']!='rule']
        if dependencies:
            names=', '.join(op['kind']+' '+op['payload'].get('name',op['payload'].get('ifname','')) for op in dependencies)
            errors.append('Required definitions need synchronization: '+names+'. Review them using the link below, then return to this rule plan.')
        item=next((i for i in plan['items'] if i['kind']=='rule' and i.get('desired')),None)
        operation=next((op for op in plan['operations'] if op['kind']=='rule'),None)
        if operation and not dependencies and any(value.startswith('@category:') for value in operation['payload'].get('categories','').split(',')):
            errors.append('Required category UUIDs are missing. Pull a live snapshot before pushing this rule.')
        if operation and operation['action']=='update' and not operation.get('remote_uuid'):
            errors.append('Pull a live snapshot with remote rule UUIDs before updating.')
        before=canonical(item['actual'] or {},item['desired'],'rule') if item and item['actual'] else {}
        after=canonical(item['desired'],item['desired'],'rule') if item else {}
        lines=list(difflib.unified_diff(json.dumps(before,indent=2,sort_keys=True).splitlines(),json.dumps(after,indent=2,sort_keys=True).splitlines(),fromfile='firewall/current',tofile='manager/desired',lineterm='')) if operation else []
        result['rows'].append({'id':str(rule.pk),'name':rule.name,'operation':operation,'errors':errors,'dependencies':dependencies,
            'diff':[{'text':line,'kind':'added' if line.startswith('+') else 'removed' if line.startswith('-') else ''} for line in lines]})
    result['approval_sha256']=digest(result)
    return result


def _execute_deployment(firewall, approved, selected, client, actor):
    plan=deployment_plan(firewall)
    if approved!=plan['approval_sha256']: raise DeviceError('Rule plan changed. Review again before applying.')
    selected=set(selected)
    eligible={row['id']:row for row in plan['rows'] if row['operation'] and not row['errors']}
    if not selected or not selected <= eligible.keys(): raise DeviceError('Select one or more unblocked rule changes from the current plan.')
    occupied=set()
    for key in selected:
        payload=eligible[key]['operation']['payload']
        for binding in payload['interface'].split(','):
            position=(binding,payload['sequence'])
            if position in occupied: raise DeviceError('Selected rules have conflicting sequence positions. Resolve ordering first.')
            occupied.add(position)
    baseline=firewall.snapshots.get(pk=plan['snapshot_id'])
    current=client.snapshot()
    if fingerprint(current)!=fingerprint(baseline.data): raise DeviceError('Device configuration changed. Pull a new snapshot and review again.')
    if deployment_plan(firewall)['approval_sha256']!=approved: raise DeviceError('Manager policy changed during preflight. Review again.')
    AuditEvent.objects.create(actor=actor,action='rules.deploy.started',detail=firewall.name+' '+approved+' '+','.join(sorted(selected)))
    try:
        rows=[row for row in plan['rows'] if row['id'] in selected]
        for row in rows: client.save_rule(row['operation'])
        client.apply_rules()
        observed=client.snapshot()
        for row in rows:
            payload=row['operation']['payload']
            matches=[r for r in observed['rules'] if r.get('description')==payload['description']]
            if len(matches)!=1 or canonical(matches[0],payload,'rule')!=canonical(payload,payload,'rule'):
                raise DeviceError('Rule readback did not match the selected changes. Inspect the firewall; partial changes may remain.')
        Snapshot.objects.create(firewall=firewall,data=observed,source='api')
        AuditEvent.objects.create(actor=actor,action='rules.deploy.completed',detail=firewall.name)
    except DeviceError:
        AuditEvent.objects.create(actor=actor,action='rules.deploy.failed',detail=firewall.name+'; partial saved or active changes may remain')
        raise
    return len(selected)


def execute_deployment(firewall, approved, selected, client, actor):
    # Local file lock serializes writes across Gunicorn threads/workers sharing
    # this data directory. A second request must review the resulting snapshot.
    import fcntl
    import os
    from django.conf import settings
    path=settings.DATA_DIR / f".rules-deploy-{firewall.pk}.lock"
    with open(path,'a',opener=lambda p,flags:os.open(p,flags,0o600)) as lock:
        try: fcntl.flock(lock,fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc: raise DeviceError('A rule deployment is already running for this firewall.') from exc
        try: return _execute_deployment(firewall,approved,selected,client,actor)
        finally: fcntl.flock(lock,fcntl.LOCK_UN)
