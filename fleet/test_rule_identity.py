import uuid
from django.test import TestCase
from django.core.exceptions import ValidationError
from .models import Firewall,LogicalInterface,InterfaceMapping,Rule,Snapshot
from .rule_identity import short_marker
from .reconcile import plan_for
from .import_rules import import_rules

EMPTY={'schema_version':1,'rules':[],'aliases':[],'groups':[],'categories':[],'interfaces':[]}

class CompactIdentityTests(TestCase):
    def setUp(self):
        self.firewall=Firewall.objects.create(name='Test',base_url='https://test.example')
        self.interface=LogicalInterface.objects.create(name='LAN')
        InterfaceMapping.objects.create(firewall=self.firewall,logical_interface=self.interface,device_interface='lan')
        self.rule=Rule.objects.create(id=uuid.UUID('6dd1349e-f6bd-4bc3-ac2b-dab08fd9cf42'),name='Allow DNS',interface=self.interface)
        self.snapshot=Snapshot.objects.create(firewall=self.firewall,data=EMPTY)
    def payload(self):
        return next(op['payload'] for op in plan_for(self.firewall)['operations'] if op['kind']=='rule')
    def test_compact_description_and_legacy_update_preserves_remote_uuid(self):
        payload=self.payload()
        self.assertEqual(payload['description'],'[om:6dd1349ef6bd] Allow DNS')
        old={**payload,'uuid':'existing-remote','description':f'[opnmanager:{self.rule.pk}] Allow DNS'}
        self.snapshot.data={**EMPTY,'rules':[old]};self.snapshot.save()
        plan=plan_for(self.firewall)
        operation=plan['operations'][0]
        self.assertEqual(operation['action'],'update')
        self.assertEqual(operation['remote_uuid'],'existing-remote')
        item=next(item for item in plan['items'] if item['kind']=='rule')
        self.assertEqual([c['field'] for c in item['changes']],['description'])
    def test_short_marker_recognized_after_rename(self):
        payload=self.payload()
        self.snapshot.data={**EMPTY,'rules':[{**payload,'uuid':'existing'}]};self.snapshot.save()
        self.assertFalse(plan_for(self.firewall)['operations'])
        self.rule.name='New description';self.rule.save()
        op=plan_for(self.firewall)['operations'][0]
        self.assertEqual(op['remote_uuid'],'existing')
        self.assertTrue(op['payload']['description'].startswith('[om:6dd1349ef6bd] '))
    def test_duplicate_short_and_legacy_remote_markers_block_writes(self):
        payload=self.payload()
        self.snapshot.data={**EMPTY,'rules':[{**payload,'uuid':'one'},{**payload,'uuid':'two','description':f'[opnmanager:{self.rule.pk}] Allow DNS'}]};self.snapshot.save()
        plan=plan_for(self.firewall)
        self.assertTrue(plan['errors']);self.assertFalse(plan['operations'])
    def test_colliding_uuid_prefixes_are_rejected(self):
        Rule.objects.create(id=uuid.UUID('6dd1349e-f6bd-4bc3-ac2b-dab08fd9cf43'),name='Collision',interface=self.interface,sequence=200)
        plan=plan_for(self.firewall)
        self.assertTrue(any('identity collision' in e for e in plan['errors']))
        self.assertFalse(plan['operations'])
    def test_compact_markers_cannot_be_reimported_and_remain_managed_out_of_scope(self):
        payload=self.payload()
        self.snapshot.data={**EMPTY,'rules':[{**payload,'uuid':'remote'}]};self.snapshot.save()
        with self.assertRaisesMessage(ValidationError,'manager identity'):
            import_rules(self.snapshot,['0'],'all',[])
        self.rule.scope='selected';self.rule.save()
        self.assertEqual(plan_for(self.firewall)['items'][0]['status'],'out_of_scope')
    def test_same_human_name_without_tag_is_not_adopted(self):
        payload=self.payload()
        self.snapshot.data={**EMPTY,'rules':[{**payload,'uuid':'local','description':'Allow DNS'}]};self.snapshot.save()
        plan=plan_for(self.firewall)
        self.assertEqual(plan['operations'][0]['action'],'create')
        self.assertIn('local_only',[item['status'] for item in plan['items']])
