import json
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required,permission_required,user_passes_test
from django.core import signing
from django.http import HttpResponseBadRequest
from django.shortcuts import render,redirect,get_object_or_404
from django.views.decorators.http import require_POST
from django.views.decorators.debug import sensitive_post_parameters
from .models import Firewall,LogicalInterface,InterfaceMapping,DeviceInventory,FirmwareJob,VirtualIP,AuditEvent
from .opnsense import OPNsenseClient,DeviceError
from .system_management import refresh_inventory,firmware_action,refresh_firmware,read_vips,vip_plan
from .alias_sync import digest


def vip_lock(view):
    from functools import wraps
    @wraps(view)
    def wrapped(request,pk,*args,**kwargs):
        if request.method!='POST':return view(request,pk,*args,**kwargs)
        import fcntl,os
        with open(settings.DATA_DIR / f'.vip-{pk}.lock','a',opener=lambda p,f:os.open(p,f,0o600)) as lock:
            try:fcntl.flock(lock,fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                messages.error(request,'Another virtual IP operation is running on this firewall. Review again after it completes.')
                return redirect('virtual_ips')
            try:return view(request,pk,*args,**kwargs)
            finally:fcntl.flock(lock,fcntl.LOCK_UN)
    return wrapped


def chosen(request):
    ids=request.GET.getlist('firewalls')
    return list(Firewall.objects.filter(pk__in=[v for v in ids if v.isdigit()])) if 'firewalls' in request.GET or 'selection' in request.GET else list(Firewall.objects.all())


@login_required
@permission_required('fleet.view_firewall',raise_exception=True)
def interfaces(request,logical=False):
    devices=chosen(request);rows=[]
    mappings={(mapping.firewall_id,mapping.logical_interface_id):mapping for mapping in InterfaceMapping.objects.filter(firewall__in=devices)}
    names=list(LogicalInterface.objects.all()) if logical else sorted({r.get('name') for fw in devices for r in getattr(getattr(fw,'inventory',None),'data',{}).get('interfaces',[]) if r.get('name')})
    for item in names:
        cells=[]
        for fw in devices:
            inventory=getattr(getattr(fw,'inventory',None),'data',{})
            mapping=mappings.get((fw.pk,item.pk)) if logical else None
            local=mapping.device_interface if mapping else None if logical else item
            observed=next((r for r in inventory.get('interfaces',[]) if r['name']==local),None)
            cells.append({'firewall':fw,'mapping':mapping,'local':local,'observed':observed,'logical_id':item.pk if logical else None,'observed_at':getattr(getattr(fw,'inventory',None),'updated_at',None)})
        rows.append({'name':item.name if logical else item,'cells':cells})
    return render(request,'fleet/interface_matrix.html',{'devices':devices,'all_firewalls':Firewall.objects.all(),'rows':rows,'logical':logical})


@login_required
@permission_required(('fleet.change_interfacemapping','fleet.add_interfacemapping','fleet.view_firewall'),raise_exception=True)
@require_POST
def save_mapping(request):
    fw=get_object_or_404(Firewall,pk=request.POST.get('firewall'))
    logical=get_object_or_404(LogicalInterface,pk=request.POST.get('logical'))
    local=request.POST.get('device','').strip()
    from django.core.exceptions import ValidationError
    from django.db import IntegrityError,transaction
    if not local:
        messages.error(request,'Use the mapping editor to remove mappings explicitly.')
    else:
        try:
            with transaction.atomic():
                mapping=InterfaceMapping.objects.filter(firewall=fw,logical_interface=logical).first() or InterfaceMapping(firewall=fw,logical_interface=logical)
                mapping.device_interface=local;mapping.full_clean();mapping.save()
                AuditEvent.objects.create(actor=request.user.username,action='mapping.updated',detail=fw.name+' '+logical.name)
        except (ValidationError,IntegrityError):messages.error(request,'Invalid or duplicate device interface mapping.')
    return redirect('logical_matrix')


@login_required
@permission_required(('fleet.refresh_firewall','fleet.view_firewall'),raise_exception=True)
@require_POST
def read_interfaces(request):
    for fw in Firewall.objects.filter(pk__in=request.POST.getlist('selected_firewalls'),enabled=True):
        try:refresh_inventory(fw,OPNsenseClient(fw));messages.success(request,fw.name+': interface inventory refreshed.')
        except DeviceError as exc:messages.error(request,fw.name+': '+str(exc))
    return redirect('interface_overview')


@login_required
@permission_required('fleet.view_firewall',raise_exception=True)
def firmware(request,updates=False):
    rows=[]
    for fw in Firewall.objects.all():
        inventory=getattr(getattr(fw,'inventory',None),'data',{})
        rows.append({'firewall':fw,'status':inventory.get('firmware',{}),'job':fw.firmwarejob_set.first()})
    return render(request,'fleet/firmware.html',{'rows':rows,'updates':updates})


@login_required
@permission_required(('fleet.refresh_firewall','fleet.view_firewall'),raise_exception=True)
@require_POST
def firmware_task(request):
    action=request.POST.get('action')
    if action not in ('check','refresh','update'):return HttpResponseBadRequest('Unknown firmware action')
    if action=='update' and not request.user.has_perm('fleet.install_firmware'):
        from django.core.exceptions import PermissionDenied
        raise PermissionDenied
    if action=='update' and request.POST.get('confirm')!='yes':
        messages.error(request,'Confirm the firmware update warning first.');return redirect('firmware_updates')
    for fw in Firewall.objects.filter(pk__in=request.POST.getlist('selected_firewalls'),enabled=True):
        try:
            client=OPNsenseClient(fw)
            if action=='refresh':refresh_firmware(fw,client)
            else:firmware_action(fw,action,client,request.user.username)
            messages.success(request,fw.name+': '+action+' request completed; verify the reported device status.')
        except DeviceError as exc:messages.error(request,fw.name+': '+str(exc))
    return redirect('firmware_updates' if action=='update' else 'firmware_status')


@login_required
@permission_required('fleet.view_firewall',raise_exception=True)
def deployment_overview(request):
    return render(request,'fleet/deployment_overview.html',{'devices':Firewall.objects.all(),'jobs':FirmwareJob.objects.select_related('firewall')[:30]})


@login_required
@permission_required(('fleet.view_virtualip','fleet.view_firewall'),raise_exception=True)
def virtual_ips(request):
    return render(request,'fleet/virtual_ips.html',{'devices':Firewall.objects.all(),'desired':VirtualIP.objects.select_related('interface'),'observations':[{'firewall':fw,'rows':getattr(getattr(fw,'inventory',None),'data',{}).get('vips',[])} for fw in Firewall.objects.all()]})


@login_required
@permission_required(('fleet.view_firewall','fleet.change_virtualip','fleet.sync_definitions'),raise_exception=True)
@vip_lock
def review_vip(request,pk,vip_id):
    fw=get_object_or_404(Firewall,pk=pk,enabled=True);vip=get_object_or_404(VirtualIP,pk=vip_id)
    if not vip.applies_to(fw):return HttpResponseBadRequest('VIP does not target this firewall')
    try:
        client=OPNsenseClient(fw);observed=read_vips(client);plan=vip_plan(fw,vip,observed)
        fingerprint=digest({'observed':observed,'plan':plan})
        if request.method=='POST':
            try:approved=signing.loads(request.POST.get('approval',''),salt='vip-review',max_age=600)
            except signing.BadSignature:raise DeviceError('Virtual IP review expired or is invalid. Review again.')
            if approved!={'firewall':fw.pk,'vip':vip.pk,'digest':fingerprint}:raise DeviceError('Device or desired VIP changed. Review again.')
            from urllib.parse import quote
            endpoint='set_item/'+quote(plan['uuid'],safe='') if plan['uuid'] else 'add_item'
            AuditEvent.objects.create(actor=request.user.username,action='vip.apply.started',detail=fw.name+' '+vip.name)
            result=client.post('/api/interfaces/vip_settings/'+endpoint,{'vip':plan['payload']})
            if result.get('result')!='saved':raise DeviceError('Device rejected the VIP. Inspect validation errors.')
            if client.post('/api/interfaces/vip_settings/reconfigure',{}).get('status')!='ok':raise DeviceError('VIP saved but reconfiguration failed. Inspect device state.')
            after=read_vips(client)
            matches=[r for r in after if r.get('descr')==plan['payload']['descr']]
            import ipaddress
            if len(matches)!=1 or ipaddress.ip_interface(matches[0].get('subnet','')+'/'+matches[0].get('subnet_bits',''))!=ipaddress.ip_interface(vip.network) or matches[0].get('interface')!=plan['payload']['interface'] or matches[0].get('mode')!=vip.mode:raise DeviceError('VIP readback did not match. Inspect device state.')
            AuditEvent.objects.create(actor=request.user.username,action='vip.applied',detail=fw.name+' '+vip.name)
            messages.success(request,'VIP applied and read back.');return redirect('virtual_ips')
        token=signing.dumps({'firewall':fw.pk,'vip':vip.pk,'digest':fingerprint},salt='vip-review')
        return render(request,'fleet/vip_review.html',{'firewall':fw,'vip':vip,'plan':plan,'approval':token})
    except DeviceError as exc:
        if request.method=='POST':AuditEvent.objects.create(actor=request.user.username,action='vip.apply.failed',detail=fw.name)
        messages.error(request,str(exc));return redirect('virtual_ips')


@login_required
@user_passes_test(lambda u:u.is_superuser)
@sensitive_post_parameters('client_secret')
def oidc_options(request):
    from .forms import OIDCSettingsForm
    from .oidc_storage import FIELDS,save
    from .credentials import cipher
    path=settings.DATA_DIR / '.oidc-settings.json'
    stored=json.loads(path.read_text()) if path.exists() else {}
    mapping=dict(zip(('issuer','client_id','authorization_endpoint','token_endpoint','user_endpoint','jwks_endpoint'),FIELDS))
    initial={field:stored.get(key,getattr(settings,key,'')) for field,key in mapping.items()};initial['enabled']=stored.get('OIDC_ENABLED',settings.OIDC_ENABLED)
    form=OIDCSettingsForm(request.POST if request.method=='POST' else None,initial=initial)
    if request.method=='POST' and form.is_valid():
        data={key:form.cleaned_data[field] for field,key in mapping.items()};data['OIDC_ENABLED']=form.cleaned_data['enabled']
        if form.cleaned_data['client_secret']:data['encrypted_secret']=cipher().encrypt(form.cleaned_data['client_secret'].encode()).decode()
        elif stored.get('encrypted_secret'):data['encrypted_secret']=stored['encrypted_secret']
        elif getattr(settings,'OIDC_RP_CLIENT_SECRET',''):
            data['encrypted_secret']=cipher().encrypt(settings.OIDC_RP_CLIENT_SECRET.encode()).decode()
        if data['OIDC_ENABLED'] and not data.get('encrypted_secret'):form.add_error('client_secret','A client secret is required.')
        else:
            save(settings.DATA_DIR,data)
            AuditEvent.objects.create(actor=request.user.username,action='oidc.saved',detail='Restart required')
            messages.success(request,'OIDC settings saved. Restart the manager to activate them. Local accounts remain available.')
            return redirect('oidc_options')
    return render(request,'fleet/oidc_options.html',{'form':form})

@login_required
@permission_required(('fleet.view_dnsprofile','fleet.view_firewall'),raise_exception=True)
def dns_general(request):
    from .models import DNSProfile
    profiles=list(DNSProfile.objects.all())
    rows=[{'firewall':fw,'profiles':[profile for profile in profiles if profile.applies_to(fw)]} for fw in Firewall.objects.all()]
    return render(request,'fleet/dns_general.html',{'rows':rows})

@login_required
@permission_required(('fleet.view_firewall','fleet.view_virtualip','fleet.refresh_firewall'),raise_exception=True)
@require_POST
def refresh_vips(request):
    for fw in Firewall.objects.filter(pk__in=request.POST.getlist('selected_firewalls'),enabled=True):
        try:
            rows=read_vips(OPNsenseClient(fw))
            inventory,_=DeviceInventory.objects.get_or_create(firewall=fw)
            inventory.data={**inventory.data,'vips':rows};inventory.save()
            messages.success(request,fw.name+': virtual IP inventory refreshed.')
        except DeviceError as exc:messages.error(request,fw.name+': '+str(exc))
    return redirect('virtual_ips')


@login_required
@permission_required(('fleet.view_firewall','fleet.add_virtualip'),raise_exception=True)
@require_POST
def adopt_vip(request,pk,uuid):
    from .models import VirtualIPOrigin
    from django.db import transaction
    from django.core.exceptions import ValidationError
    fw=get_object_or_404(Firewall,pk=pk)
    rows=getattr(getattr(fw,'inventory',None),'data',{}).get('vips',[])
    row=next((r for r in rows if r.get('uuid')==str(uuid)),None)
    if not row:messages.error(request,'Refresh virtual IP inventory before adopting.');return redirect('virtual_ips')
    try:
        with transaction.atomic():
            if VirtualIPOrigin.objects.filter(firewall=fw,remote_uuid=str(uuid)).exists():raise DeviceError('This virtual IP has already been adopted.')
            if row.get('mode') not in ('ipalias','proxyarp'):raise DeviceError('Only IP Alias and Proxy ARP definitions can be adopted here; manage CARP on-device.')
            mapping=fw.interface_mappings.filter(device_interface=row.get('interface')).first()
            if not mapping:raise DeviceError('Map this virtual IP interface to a logical interface first.')
            desired=VirtualIP(name=(fw.name[:40]+' '+row.get('subnet','')[:45]+' '+str(uuid)[:8])[:100],interface=mapping.logical_interface,
                              network=row.get('subnet','')+'/'+row.get('subnet_bits',''),mode=row['mode'],scope='selected')
            desired.full_clean();desired.save();desired.firewalls.add(fw)
            VirtualIPOrigin.objects.create(firewall=fw,virtual_ip=desired,remote_uuid=str(uuid))
            AuditEvent.objects.create(actor=request.user.username,action='vip.adopted',detail=fw.name)
            messages.success(request,'Virtual IP adopted into manager definitions; device unchanged.')
    except (DeviceError,ValidationError) as exc:messages.error(request,str(exc))
    return redirect('virtual_ips')


@login_required
@permission_required(('fleet.view_firewall','fleet.delete_virtualip','fleet.sync_definitions'),raise_exception=True)
@vip_lock
def delete_vip(request,pk,uuid):
    fw=get_object_or_404(Firewall,pk=pk,enabled=True)
    try:
        client=OPNsenseClient(fw);rows=read_vips(client)
        row=next((r for r in rows if r.get('uuid')==str(uuid)),None)
        if not row:raise DeviceError('Virtual IP no longer exists. Refresh inventory.')
        if row.get('mode')=='carp':raise DeviceError('CARP deletion is device-local because of HA dependencies.')
        expected={'firewall':fw.pk,'uuid':str(uuid),'digest':digest(rows)}
        if request.method=='POST':
            try:approved=signing.loads(request.POST.get('approval',''),salt='vip-delete',max_age=600)
            except signing.BadSignature:raise DeviceError('Deletion review expired. Review again.')
            if approved!=expected:raise DeviceError('Virtual IP configuration changed. Review again.')
            AuditEvent.objects.create(actor=request.user.username,action='vip.delete.started',detail=fw.name+' '+str(uuid))
            result=client.post('/api/interfaces/vip_settings/del_item/'+str(uuid),{})
            if result.get('result')!='deleted':raise DeviceError('The device refused deletion, possibly because the VIP is in use.')
            if client.post('/api/interfaces/vip_settings/reconfigure',{}).get('status')!='ok':raise DeviceError('VIP removed from saved config but reconfiguration failed; inspect device state.')
            after=read_vips(client)
            if any(r.get('uuid')==str(uuid) for r in after):raise DeviceError('Deleted VIP is still present on readback.')
            inventory,_=DeviceInventory.objects.get_or_create(firewall=fw);inventory.data={**inventory.data,'vips':after};inventory.save()
            AuditEvent.objects.create(actor=request.user.username,action='vip.delete.completed',detail=fw.name+' '+str(uuid))
            messages.success(request,'Virtual IP deleted and absence verified. Retarget or remove any desired definition separately.')
            return redirect('virtual_ips')
        return render(request,'fleet/vip_delete.html',{'firewall':fw,'row':row,'approval':signing.dumps(expected,salt='vip-delete')})
    except DeviceError as exc:
        if request.method=='POST':AuditEvent.objects.create(actor=request.user.username,action='vip.delete.failed',detail=fw.name)
        messages.error(request,str(exc));return redirect('virtual_ips')
