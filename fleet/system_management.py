import json
from django.core.exceptions import ValidationError
from .models import DeviceInventory, FirmwareJob, AuditEvent
from .opnsense import DeviceError, flatten


def refresh_inventory(firewall,client):
    response=client.post('/api/interfaces/overview/interfaces_info',{'current':1,'rowCount':-1,'searchPhrase':''})
    rows=response.get('rows') if isinstance(response,dict) else None
    if not isinstance(rows,list):raise DeviceError('Unsupported interface inventory response.')
    interfaces=[]
    for row in rows:
        config=row.get('config',{})
        identifier=config.get('identifier') or row.get('identifier') or row.get('device')
        if not identifier:continue
        item={key:row.get(key,'') for key in ('description','device','status','ipv4','ipv6','mtu','macaddr','vlan_tag','gateways')}
        for family in ('ipv4','ipv6'):
            addresses=item.get(family)
            if isinstance(addresses,list):item[family]=', '.join(str(ip.get('ipaddr','')) if isinstance(ip,dict) else str(ip) for ip in addresses)
        item['name']=identifier;interfaces.append(item)
    obj,_=DeviceInventory.objects.get_or_create(firewall=firewall)
    data={**obj.data,'interfaces':interfaces}
    # Rule field choices are device-native. A missing privilege shouldn't erase
    # interface observations or pretend a fallback list is the complete catalog.
    try:
        rule=client.get('/api/firewall/filter/get_rule')['rule']
        choices=[]
        for value,option in rule.get('protocol',{}).items():
            canonical='any' if value.lower()=='any' else 'IPv6-ICMP' if value.lower()=='ipv6-icmp' else value.upper()
            choices.append([canonical,str(option.get('value',option.get('label',value)))])
        if choices:data['protocols']=choices
        data.pop('catalog_error',None)
    except (DeviceError,KeyError,TypeError,AttributeError):data['catalog_error']='Device protocol catalog unavailable; existing catalog retained.'
    obj.data=data;obj.save()
    return obj


def _firmware_action(firewall,action,client,actor):
    if not firewall.enabled:raise DeviceError('Disabled firewalls cannot receive firmware actions.')
    if action not in ('check','update'):raise DeviceError('Unsupported firmware action.')
    if action=='update':
        current=client.get('/api/core/firmware/status')
        if current.get('status')!='update': raise DeviceError('Run a successful firmware check first. Only stable package updates are supported here.')
    job=FirmwareJob.objects.create(firewall=firewall,action=action,status='starting')
    AuditEvent.objects.create(actor=actor,action='firmware.'+action+'.started',detail=firewall.name)
    try:
        running=client.get('/api/core/firmware/running')
        if str(running.get('status','')).strip() != 'ready':
            raise DeviceError('The firewall already has a firmware task running. Refresh its status first.')
        result=client.post('/api/core/firmware/'+action,{})
        if not isinstance(result,dict) or result.get('status')!='ok':raise DeviceError('Firmware task was not accepted by OPNsense.')
        job.status='running';job.remote_id=str(result.get('msg_uuid',''))[:100]
        job.message='Remote task accepted; refresh status to monitor completion. No automatic reboot is requested.'
    except DeviceError as exc:
        job.status='uncertain';job.message=str(exc);job.save()
        AuditEvent.objects.create(actor=actor,action='firmware.'+action+'.uncertain',detail=firewall.name)
        raise
    job.save();return job


def refresh_firmware(firewall,client):
    response=client.get('/api/core/firmware/status')
    if not isinstance(response,dict):raise DeviceError('Unsupported firmware status response.')
    product=response.get('product') or {}
    safe={'status':str(response.get('status','unknown')), 'version':str(product.get('product_version','unknown')),
          'message':str(response.get('status_msg',''))[:500]}
    inventory,_=DeviceInventory.objects.get_or_create(firewall=firewall)
    inventory.data={**inventory.data,'firmware':safe};inventory.save()
    job=firewall.firmwarejob_set.filter(status__in=['running','starting','uncertain']).first()
    if job:
        progress=client.get('/api/core/firmware/upgradestatus')
        state=progress.get('status','unknown')
        if state in ('done','reboot','error'):
            job.status={'done':'finished','reboot':'reboot_required','error':'uncertain'}[state]
            job.message='Device reported '+state+'. Verify version and status; completion is not a guarantee of upgrade success.'
            if state=='error' and client.get('/api/core/firmware/running').get('status')=='ready':
                job.status='unconfirmed';job.message='No active firmware task; previous result is unknown. Verify the device before explicitly retrying.'
            job.save()
    return safe


def vip_plan(firewall,desired,observed):
    mapping=firewall.interface_mappings.filter(logical_interface=desired.interface).first()
    if not mapping:raise DeviceError('Map the virtual IP logical interface on this firewall first.')
    marker='[opnmanager-vip:'+str(desired.pk)+'] '+desired.name
    payload={'interface':mapping.device_interface,'network':desired.network,'mode':desired.mode,'descr':marker}
    origin=firewall.virtualiporigin_set.filter(virtual_ip=desired).first()
    matches=[row for row in observed if row.get('descr','').startswith('[opnmanager-vip:'+str(desired.pk)+'] ') or (origin and row.get('uuid')==origin.remote_uuid)]
    if len(matches)>1:raise DeviceError('Duplicate managed virtual IP identity.')
    actual=matches[0] if matches else None
    if actual and actual.get('mode')=='carp':raise DeviceError('CARP entries require device-specific secrets and cannot be edited here.')
    return {'payload':payload,'uuid':actual.get('uuid') if actual else None}


def read_vips(client):
    response=client.get('/api/interfaces/vip_settings/get')
    nodes=response.get('vip',{}).get('vip',{})
    if nodes==[]:return []
    if not isinstance(nodes,dict):raise DeviceError('Unsupported virtual IP inventory.')
    return [{**{key:flatten(value) for key,value in row.items() if key!='password'},'uuid':uid} for uid,row in nodes.items()]


def firmware_action(firewall,action,client,actor):
    import fcntl,os
    from django.conf import settings
    with open(settings.DATA_DIR / f'.firmware-{firewall.pk}.lock','a',opener=lambda p,f:os.open(p,f,0o600)) as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:raise DeviceError('Another firmware request is being queued for this device.') from exc
        try:
            if FirmwareJob.objects.filter(firewall=firewall,status__in=['running','starting','uncertain']).exists():raise DeviceError('Refresh and resolve the existing firmware task before starting another.')
            return _firmware_action(firewall,action,client,actor)
        finally:fcntl.flock(lock,fcntl.LOCK_UN)
