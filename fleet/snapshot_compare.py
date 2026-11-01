"""Semantic preflight comparison, retaining all unrecognized configuration fields."""
from .reconcile import canonical, RULE_DEFAULTS

COLLECTIONS={'rules':'rule','aliases':'alias','groups':'group','categories':'category','interfaces':'interface'}
# These are model/UI annotations, not packet-filter configuration. Never ignore
# arbitrary unknown fields: gateways, schedules, state tuning, etc. must still block.
ANNOTATIONS={'audit','sort_order','prio_group','created','updated','category_colors'}
# PF table evaluation and traffic statistics change while packets are processed.
# Scope this explicit list to aliases: do not ignore unknown *_p/*_b fields or
# other numeric fields that could be actual configuration.
RUNTIME_FIELDS={'alias':{'eval_match','eval_nomatch','in_pass_b','in_pass_p',
                         'out_pass_b','out_pass_p','in_block_b','in_block_p',
                         'out_block_b','out_block_p'}}
DEFAULTS={
    'rule':{**RULE_DEFAULTS,'statetype':'keep','allowopts':'0','tcpflags_any':'0'},
    'alias':{'enabled':'1','description':''},
    'group':{'nogroup':'0','sequence':'0','descr':''},
    'category':{'auto':'0','color':''},
    'interface':{},
}


def normalize_row(row,kind):
    cleaned={key:value for key,value in row.items() if key not in ANNOTATIONS and key not in RUNTIME_FIELDS.get(kind,set()) and not key.startswith('alias_meta_')}
    fields={**DEFAULTS[kind],**cleaned}
    normalized=canonical({**DEFAULTS[kind],**cleaned},fields,kind)
    for key in ('sequence',):
        if normalized.get(key,'').isdigit():normalized[key]=str(int(normalized[key]))
    for key,default in DEFAULTS[kind].items():
        if default in ('0','1') and normalized.get(key,'').lower() in ('true','false'):
            normalized[key]='1' if normalized[key].lower()=='true' else '0'
    if 'received-on' in normalized:
        normalized['received-on']=','.join(sorted(set(v.strip() for v in normalized['received-on'].split(',') if v.strip())))
    # Empty optional model fields and absent fields are equivalent; nonempty
    # unknown fields remain intact and are deliberately not guessed at.
    return {key:value for key,value in normalized.items() if value!=''}


def rows_by_identity(data,collection):
    import json
    kind=COLLECTIONS[collection]
    result={}
    for index,row in enumerate(data.get(collection,[])):
        identity=row.get('uuid') or row.get('ifname') or row.get('name') or 'row:'+str(index)
        normalized=normalize_row(row,kind)
        # Preserve duplicates rather than letting an identity collision hide changes.
        result.setdefault(str(identity),[]).append(normalized)
    return {key:sorted(rows,key=lambda r:json.dumps(r,sort_keys=True)) for key,rows in result.items()}


def configuration_changes(before,after):
    changes=[]
    for collection in COLLECTIONS:
        left,right=rows_by_identity(before,collection),rows_by_identity(after,collection)
        for identity in sorted(left.keys()|right.keys()):
            if left.get(identity)==right.get(identity):continue
            if identity not in left:detail='added'
            elif identity not in right:detail='removed'
            elif len(left[identity])!=1 or len(right[identity])!=1:detail='duplicate identities or changed duplicate entries'
            else:
                a,b=left[identity][0],right[identity][0]
                detail='fields '+', '.join(sorted(key for key in a.keys()|b.keys() if a.get(key)!=b.get(key)))
            changes.append(f'{collection} {identity}: {detail}')
    if before.get('schema_version')!=after.get('schema_version'):changes.append('snapshot schema_version changed')
    return changes
