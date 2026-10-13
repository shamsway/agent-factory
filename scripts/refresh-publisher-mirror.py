#!/usr/bin/python3
"""PREPARE ONLY: root imports one approved local bundle, never fetches a remote."""
import argparse,fcntl,hashlib,json,os,pwd,re,stat,subprocess
from pathlib import Path
ROOT=Path('/opt/factory-publisher/octant-private')
SCOPE=Path('/etc/factory-publisher/scope.json')
SCOPE_SHA='4dbb4daeced6eaeeb78f275aec4ec607159ac294505871eb7f7b3a68252bcfa5'
def main():
    p=argparse.ArgumentParser();p.add_argument('commit');p.add_argument('bundle',type=Path);p.add_argument('sha256');a=p.parse_args()
    assert os.geteuid()==0 and os.uname().nodename.split('.')[0]=='barlow','root_barlow_required'
    assert re.fullmatch('[0-9a-f]{40}',a.commit) and re.fullmatch('[0-9a-f]{64}',a.sha256),'hash_invalid'
    assert a.bundle.is_absolute() and a.bundle.parent==Path('/root') and not a.bundle.is_symlink(),'root_bundle_required'
    s=a.bundle.stat();assert s.st_uid==0 and stat.S_ISREG(s.st_mode) and not s.st_mode&0o077,'bundle_permissions'
    assert 0<s.st_size<=128*1024*1024,'bundle_size'
    assert hashlib.sha256(a.bundle.read_bytes()).hexdigest()==a.sha256,'bundle_hash'
    assert hashlib.sha256(SCOPE.read_bytes()).hexdigest()==SCOPE_SHA,'scope_changed'
    fd=os.open('/run/factory-publisher-acceptance.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        def run(args):
            r=subprocess.run(args,capture_output=True,timeout=180,env={'PATH':'/usr/bin:/bin','HOME':'/root','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_NO_REPLACE_OBJECTS':'1'})
            assert r.returncode in ((0,3) if args[:2]==['systemctl','is-active'] else (0,)),'git_or_unit_check_failed'
            return r.stdout
        for unit in ('factory-publisher.service','factory-publisher-check.service'):
            assert run(['systemctl','is-active',unit]).strip()==b'inactive','unit_active'
        user=pwd.getpwnam('factory-publisher')
        assert ROOT.lstat().st_uid==user.pw_uid and stat.S_IMODE(ROOT.lstat().st_mode)==0o550 and not ROOT.is_symlink(),'mirror_owner'
        for q in ROOT.rglob('*'):
            t=q.lstat();assert not q.is_symlink() and t.st_uid==0 and not t.st_mode&0o022 and (q.is_dir() or q.is_file()),'unsafe_mirror_content'
        git=['git','-c','safe.directory='+str(ROOT),'-c','core.hooksPath=/dev/null','-c','core.fsmonitor=false','-c','maintenance.auto=false','-c','gc.auto=0','-c','fetch.recurseSubmodules=false','-C',str(ROOT)]
        assert not run(git+['remote']).strip(),'remote_present'
        assert not (ROOT/'objects/info/alternates').exists() and not (ROOT/'refs/replace').exists(),'unsafe_object_sources'
        for q in [ROOT,*ROOT.rglob('*')]:assert not q.is_symlink(),'mirror_symlink'
        run(git+['fetch','--no-tags','--no-write-fetch-head',str(a.bundle),a.commit+':refs/heads/acceptance-'+a.commit])
        assert run(git+['cat-file','-t',a.commit]).strip()==b'commit','commit_missing'
        assert not run(git+['remote']).strip(),'remote_added'
        assert not (ROOT/'objects/info/alternates').exists() and not run(git+['for-each-ref','refs/replace']).strip(),'unsafe_object_sources'
        user=pwd.getpwnam('factory-publisher')
        for q in [ROOT,*ROOT.rglob('*')]:
            assert not q.is_symlink() and (q.is_file() or q.is_dir()),'mirror_type'
            os.chown(q,0,user.pw_gid);q.chmod(0o750 if q.is_dir() else 0o640)
        os.chown(ROOT,user.pw_uid,user.pw_gid);ROOT.chmod(0o550)
        # All approved file paths must still be tracked regular, bounded blobs at the new commit.
        code='''import json,subprocess,sys
from factory.investigation_scope import load_policy
p=load_policy(sys.argv[1],repository='shamsway/octant-private')
for job,namespace,paths in p.bindings:
 for path in paths:
  args=['git','--no-replace-objects','-C',sys.argv[2]]
  row=subprocess.run(args+['ls-tree','-z',sys.argv[3],'--',path],check=True,capture_output=True).stdout
  mode,kind,blob=row.split(b'\\t',1)[0].split()
  assert mode in (b'100644',b'100755') and kind==b'blob' and row.split(b'\\t',1)[1]==path.encode()+b'\\0'
  size=subprocess.run(args+['cat-file','-s',blob.decode()],check=True,capture_output=True).stdout
  assert 0<int(size)<=1024*1024
print('scope_valid')
'''
        run(['/usr/sbin/runuser','-u','factory-publisher','--','/opt/factory-publisher/venv/bin/python','-I','-c',code,str(SCOPE),str(ROOT),a.commit])
        print(json.dumps({'state':'refreshed','commit':a.commit,'scope_sha256':SCOPE_SHA,'bindings':14,'remote':False}))
    finally:os.close(fd)
if __name__=='__main__':
    try:main()
    except Exception:print('{"state":"refused","code":"mirror_refresh_failed"}');raise SystemExit(1)
