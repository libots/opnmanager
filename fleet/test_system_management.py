import tempfile
from pathlib import Path
from unittest.mock import Mock,patch
from django.test import TestCase,override_settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from .models import Firewall,LogicalInterface,InterfaceMapping,Rule,DeviceInventory,FirmwareJob,VirtualIP,DNSProfile,AuthenticationServer,FirewallAdministration
from .system_management import refresh_inventory,firmware_action,refresh_firmware,read_vips,vip_plan
from .opnsense import DeviceError
from .forms import RuleForm,CategoryForm,AuthenticationServerForm
from .reconcile import plan_for
from .oidc_storage import load

EMPTY={'schema_version':1,'rules':[],'aliases':[],'interfaces':[],'groups':[],'categories':[]}

class SystemManagementTests(TestCase):
    def setUp(self):
        self.fw=Firewall.objects.create(name='One',base_url='https://one.test')
        self.logical=LogicalInterface.objects.create(name='LAN')
        InterfaceMapping.objects.create(firewall=self.fw,logical_interface=self.logical,device_interface='lan')
        self.admin=get_user_model().objects.create_superuser('test-admin',password='Test-only-password')
        self.client.force_login(self.admin)
    def test_inventory_reads_addresses_and_device_protocol_catalog_without_secrets(self):
        client=Mock()
        client.post.return_value={'rows':[{'identifier':'lan','device':'igc0','description':'Clients','ipv4':[{'ipaddr':'192.0.2.1/24'}],'ipv6':[],'status':'up','config':{'password':'do-not-store'}}]}
        client.get.return_value={'rule':{'protocol':{'tcp':{'value':'TCP','selected':0},'ospf':{'value':'OSPF','selected':0}}}}
        inventory=refresh_inventory(self.fw,client)
        self.assertEqual(inventory.data['interfaces'][0]['ipv4'],'192.0.2.1/24')
        self.assertNotIn('do-not-store',str(inventory.data))
        self.assertIn(['OSPF','OSPF'],inventory.data['protocols'])
        self.assertIn(('OSPF','OSPF'),list(RuleForm().fields['protocol'].widget.choices))
        self.assertContains(self.client.get('/interfaces/'),'192.0.2.1/24')
        self.assertContains(self.client.get('/fleet/logical-interfaces/'),'Save mapping')
    def test_matrix_empty_selection_and_mapping_edit(self):
        self.assertNotContains(self.client.get('/interfaces/?selection=1'),'<th>One</th>',html=False)
        self.client.post('/fleet/mappings/save/',{'firewall':self.fw.pk,'logical':self.logical.pk,'device':'opt2'})
        self.assertEqual(self.fw.interface_mappings.get().device_interface,'opt2')
    def test_protocol_origin_and_builtin_rule_options(self):
        from .models import Snapshot
        Snapshot.objects.create(firewall=self.fw,data=EMPTY)
        rule=Rule.objects.create(name='Origin',interface=self.logical,source='bogons',destination='(self)')
        rule.origin_interfaces.add(self.logical)
        op=next(op for op in plan_for(self.fw)['operations'] if op['kind']=='rule')
        self.assertEqual(op['payload']['received-on'],'lan')
        form=RuleForm()
        self.assertIn('bogonsv6',str(form['source']))
        self.assertIn('https',str(form['destination_port']))
        self.assertContains(self.client.get('/admin/fleet/rule/add/'),'Organization')
        self.assertContains(self.client.get('/admin/fleet/rule/add/'),'Interface (origin)')
    def test_category_picker_round_trips_hex_value(self):
        form=CategoryForm({'name':'Color','color':'#abcdef','scope':'all'})
        self.assertTrue(form.is_valid(),form.errors)
        self.assertEqual(form.save().color,'abcdef')
        self.assertIn('type="color"',str(form['color']))
    def test_firmware_check_is_async_and_busy_rejected(self):
        client=Mock();client.get.return_value={'status':'ready'};client.post.return_value={'status':'ok','msg_uuid':'job'}
        job=firmware_action(self.fw,'check',client,'test')
        self.assertEqual(job.status,'running')
        client.post.assert_called_once_with('/api/core/firmware/check',{})
        with self.assertRaisesMessage(DeviceError,'existing firmware task'):firmware_action(self.fw,'check',client,'test')
        job.status='finished';job.save();client.get.return_value={'status':'busy'}
        with self.assertRaisesMessage(DeviceError,'already has'):firmware_action(self.fw,'check',client,'test')
    def test_stable_update_requires_current_offer_and_accepted_does_not_mean_finished(self):
        client=Mock();client.get.side_effect=[{'status':'update'},{'status':'ready'}];client.post.return_value={'status':'ok','msg_uuid':'job'}
        job=firmware_action(self.fw,'update',client,'test')
        self.assertEqual(job.status,'running')
        client.post.assert_called_once_with('/api/core/firmware/update',{})
        client.get.side_effect=[{'status':'ok','product':{'product_version':'26.1'}},{'status':'done'}]
        refresh_firmware(self.fw,client);job.refresh_from_db()
        self.assertEqual(job.status,'finished')
        self.assertIn('not a guarantee',job.message)
    def test_firmware_failures_and_confirmation(self):
        client=Mock();client.get.return_value={'status':'none'}
        with self.assertRaisesMessage(DeviceError,'successful firmware check'):firmware_action(self.fw,'update',client,'test')
        client.post.assert_not_called()
        with patch('fleet.management_views.OPNsenseClient') as factory:
            self.client.post('/system/firmware/action/',{'action':'update','selected_firewalls':[self.fw.pk]})
            factory.assert_not_called()
    def test_desired_profiles_preserve_domain_order_and_credentials_are_encrypted(self):
        profile=DNSProfile(name='Domains',search_domains='corp.example\nlab.example');profile.full_clean();profile.save()
        self.assertEqual(profile.search_domains,'corp.example\nlab.example')
        with self.assertRaises(ValidationError):DNSProfile(name='Invalid',search_domains='invalid domain').full_clean()
        with tempfile.TemporaryDirectory() as directory,override_settings(DATA_DIR=Path(directory)):
            form=AuthenticationServerForm({'name':'LDAP','host':'ldap.example','port':636,'kind':'ldap','scope':'all','use_tls':'on','secret':'test-bind-secret'})
            self.assertTrue(form.is_valid(),form.errors);server=form.save()
            self.assertNotIn('test-bind-secret',server.encrypted_secret)
            self.assertNotIn('test-bind-secret',str(AuthenticationServerForm(instance=server)))
            policy=FirewallAdministration.objects.create(name='Auth');policy.authentication_servers.add(server)
            self.assertTrue(policy.applies_to(self.fw))
        self.assertContains(self.client.get('/system/settings/general/'),'not deployed')
    def test_oidc_ui_is_write_only_encrypted_restart_configuration(self):
        payload={'enabled':'on','issuer':'https://id.test','client_id':'manager','client_secret':'test-client-secret',
                 'authorization_endpoint':'https://id.test/auth','token_endpoint':'https://id.test/token','user_endpoint':'https://id.test/user','jwks_endpoint':'https://id.test/keys'}
        with tempfile.TemporaryDirectory() as directory,override_settings(DATA_DIR=Path(directory)):
            response=self.client.post('/settings/authentication/',payload,follow=True)
            self.assertContains(response,'Restart the manager')
            self.assertNotContains(response,'test-client-secret')
            raw=(Path(directory)/'.oidc-settings.json').read_text()
            self.assertNotIn('test-client-secret',raw)
            self.assertEqual(load(Path(directory))['OIDC_RP_CLIENT_SECRET'],'test-client-secret')
            self.assertEqual((Path(directory)/'.oidc-settings.json').stat().st_mode & 0o077,0)
    def test_virtual_ip_mapping_identity_and_secret_redaction(self):
        desired=VirtualIP.objects.create(name='Service',interface=self.logical,network='192.0.2.5/24')
        plan=vip_plan(self.fw,desired,[])
        self.assertEqual(plan['payload']['interface'],'lan')
        client=Mock();client.get.return_value={'vip':{'vip':{'remote':{'interface':'lan','mode':'ipalias','password':'never-show','descr':plan['payload']['descr'],'subnet':'192.0.2.5','subnet_bits':'24'}}}}
        rows=read_vips(client);self.assertNotIn('password',rows[0])
        desired.name='Renamed';desired.save()
        self.assertEqual(vip_plan(self.fw,desired,rows)['uuid'],'remote')
        with self.assertRaises(ValidationError):VirtualIP(name='Bad',interface=self.logical,network='192.0.2.5').full_clean()
    def test_menu_routes_keep_account_controls_and_permission_boundaries(self):
        for url in ['/','/fleet/deployment/','/fleet/logical-interfaces/','/interfaces/','/interfaces/virtual-ips/','/system/firmware/status/','/system/firmware/updates/','/settings/authentication/']:
            response=self.client.get(url);self.assertEqual(response.status_code,200,url)
            self.assertContains(response,'Firewall System');self.assertContains(response,'Change password')
        basic=get_user_model().objects.create_user('basic');self.client.force_login(basic)
        self.assertEqual(self.client.post('/system/firmware/action/',{'action':'update','confirm':'yes'}).status_code,403)
        self.assertEqual(self.client.get('/interfaces/').status_code,403)
        self.assertEqual(self.client.get('/settings/authentication/').status_code,302)

    def test_vip_adoption_and_signed_delete_stale_checks(self):
        import uuid
        uid=str(uuid.uuid4())
        rows=[{'uuid':uid,'subnet':'192.0.2.5','subnet_bits':'24','interface':'lan','mode':'ipalias','descr':'Existing'}]
        DeviceInventory.objects.create(firewall=self.fw,data={'vips':rows})
        response=self.client.post(f'/interfaces/virtual-ips/{self.fw.pk}/adopt/{uid}/')
        self.assertEqual(response.status_code,302)
        desired=VirtualIP.objects.get()
        self.assertEqual(vip_plan(self.fw,desired,rows)['uuid'],uid)
        self.assertContains(self.client.get('/interfaces/virtual-ips/'),'192.0.2.5')
        with patch('fleet.management_views.OPNsenseClient') as factory:
            device=factory.return_value
            device.get.return_value={'vip':{'vip':{uid:{key:value for key,value in rows[0].items() if key!='uuid'}}}}
            preview=self.client.get(f'/interfaces/virtual-ips/{self.fw.pk}/delete/{uid}/')
            self.assertEqual(preview.status_code,200)
            token=preview.context['approval']
            device.get.return_value={'vip':{'vip':{uid:{'subnet':'192.0.2.6','subnet_bits':'24','interface':'lan','mode':'ipalias'}}}}
            self.client.post(f'/interfaces/virtual-ips/{self.fw.pk}/delete/{uid}/',{'approval':token})
            device.post.assert_not_called()

    def test_vip_review_apply_verifies_network_and_interface(self):
        desired=VirtualIP.objects.create(name='Service',interface=self.logical,network='192.0.2.5/24')
        marker=f'[opnmanager-vip:{desired.pk}] Service'
        with patch('fleet.management_views.OPNsenseClient') as factory:
            device=factory.return_value
            device.get.return_value={'vip':{'vip':{}}}
            response=self.client.get(f'/interfaces/virtual-ips/{self.fw.pk}/{desired.pk}/')
            token=response.context['approval']
            device.get.side_effect=[{'vip':{'vip':{}}},{'vip':{'vip':{'new':{'subnet':'192.0.2.5','subnet_bits':'24','interface':'lan','mode':'ipalias','descr':marker}}}}]
            device.post.side_effect=[{'result':'saved'},{'status':'ok'}]
            self.client.post(f'/interfaces/virtual-ips/{self.fw.pk}/{desired.pk}/',{'approval':token})
            self.assertEqual(device.post.call_count,2)
            self.assertEqual(device.post.call_args_list[0].args[0],'/api/interfaces/vip_settings/add_item')
            from .models import AuditEvent
            self.assertTrue(AuditEvent.objects.filter(action='vip.applied').exists())
