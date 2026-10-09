"""Root-only metadata checks. Never opens key; never emits provider/config text."""
import hashlib,json,os,stat,sys,time
from pathlib import Path
from factory.publisher_credentials import protected_read
from factory import investigation_evidence as e,publisher_status
POLICY=Path('/etc/factory-publisher/policy.json')
STATE=Path('/var/lib/factory-publisher/state')
LOGIN='shamsway-factory-findings[bot]'
def read(path,limit=65536,*,owners=None):
    raw=protected_read(path,maximum=limit,owners=owners)
    return json.loads(raw,object_pairs_hook=e.unique_pairs)
def policy():
    p=read(POLICY)
    assert p['version']==2 and p['app']['repository']=='shamsway/octant-private','policy_invalid'
    assert p['app']['login']==LOGIN and p['enabled'] is False and p['allow_publish'] is False,'switches_or_identity_invalid'
    assert p['app']['key_file']=='/run/credentials/factory-publisher.service/app-key','key_path_invalid'
    assert type(p["publisher_uid"]) is int and p["publisher_uid"] > 0,"publisher_uid_invalid"
    return p

def tree(root):
    result={}
    if root.exists():
        for p in [root,*root.rglob('*')]:
            assert not p.is_symlink(),'outbox_symlink'
            assert p.is_dir() or p.is_file(),'outbox_type'
            result[str(p.relative_to(root))]={'mode':stat.S_IMODE(p.stat().st_mode),'uid':p.stat().st_uid,
                'sha256':hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None}
    return result

def before(work):
    policy()
    snapshot={'policy_sha256':hashlib.sha256(protected_read(POLICY)).hexdigest(),
              'outbox':tree(STATE/'investigation-outbox'),
              'state':{k:v for k,v in tree(STATE).items() if k != 'publisher-token-status.json'}}
    (work/'before.json').write_text(json.dumps(snapshot,sort_keys=True))

def after(work):
    p=policy();old=read(work/'before.json')
    assert old['policy_sha256']==hashlib.sha256(protected_read(POLICY)).hexdigest(),'policy_changed'
    assert old['outbox']==tree(STATE/'investigation-outbox'),'outbox_changed'
    assert old['state']=={k:v for k,v in tree(STATE).items() if k != 'publisher-token-status.json'},'unexpected_state_change'
    result=read(work/'result.json',owners={0,p['publisher_uid']})
    assert set(result) in ({'state','login'},{'state','login','status_write_failed'}),'result_fields'
    assert result.get('state')=='read_verified' and result.get('login')==LOGIN and not result.get('status_write_failed',False),'verification_failed'
    audit=read(STATE/'publisher-token-status.json',owners={0,p['publisher_uid']})
    assert set(audit)=={'version','outcome','expires_at','requests','max_requests','valid'},'audit_fields'
    assert type(audit['version']) is int and audit['version']==1 and audit['outcome']=='ready' and type(audit['requests']) is int and audit['requests']==3 and type(audit['max_requests']) is int and audit['max_requests']==3 and audit['valid'] is True,'audit_invalid'
    assert type(audit['expires_at']) in (float,int) and time.time()<audit['expires_at']<=time.time()+3660,'expiry_invalid'
    status=read(Path(p['status_file']),owners={0,p['publisher_uid']});publisher_status.schema(status,p['app']['repository'])
    assert 0<=time.time()-e.timestamp(status['at'])<=60,'status_not_refreshed'
    assert status['token']['outcome']=='ready' and status['token']['expires_at']==audit['expires_at'],'status_token_invalid'
    # Closed durable audit/status schemas contain no bearer token. Do not scan/decrypt the App key.
    print(json.dumps({'state':'read_verified','login':LOGIN,'token_outcome':audit['outcome'],
        'token_expiry':audit['expires_at'],'request_count':4,'app_request_count':audit['requests'],
        'repository_verification_requests':1,'token_persisted':False,'outbox_unchanged':True}))
if __name__=='__main__':
    try:
        {'before':before,'after':after}[sys.argv[1]](Path(sys.argv[2]))
    except Exception:
        print('{"state":"refused","code":"a2_metadata_check_failed"}',file=sys.stderr);sys.exit(1)
