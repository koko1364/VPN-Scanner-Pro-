import urllib.request, base64, json, re, concurrent.futures, socket
from urllib.parse import urlsplit, parse_qs
from pathlib import Path
SOURCES = [
"https://raw.githubusercontent.com/A-K-6/v2ray_scrapper_repo/main/instagram_respina.txt",
"https://raw.githubusercontent.com/A-K-6/v2ray_scrapper_repo/main/youtube_respina.txt",
"https://raw.githubusercontent.com/A-K-6/v2ray_scrapper_repo/main/subscription.txt",
"https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/top100.txt",
"https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs_base64.txt",
"https://molido-sub.hidooch980.workers.dev/ios",
"https://raw.githubusercontent.com/hidooch980/vpn-sub/sub/fastest.txt",
"https://raw.githubusercontent.com/CNT-Cafe/Public-Configs/main/%E2%9C%A7%20Public%20Configs",
"https://raw.githubusercontent.com/Bllare/V2ray-Configs/main/MCI",
"https://raw.githubusercontent.com/Bllare/V2ray-Configs/main/Irancell",
"http://sub.vlessfo.ru/vlessforu/working_configs.txt",
"https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/iran.txt",
"https://raw.githubusercontent.com/drmikecrypto/PulseConfigs/main/top5_iran.txt",
"https://raw.githubusercontent.com/drmikecrypto/PulseConfigs/main/verified/configs_base64.txt",
"https://raw.githubusercontent.com/mheidari98/.proxy/main/all"
]
def decode(s):
    return base64.urlsafe_b64decode(s+'='*(-len(s)%4)).decode()
def fetch(url):
    try:
        s=urllib.request.urlopen(url,timeout=20).read(4000000).decode()
        if '://' not in s: s=decode(s.strip())
        return re.findall(r'(?m)^(?:vless|vmess|trojan|ss|hysteria2|hy2)://[^\r\n]+',s)
    except Exception as e:
        print(url, str(e)); return []
def inspect(s):
    try:
        u=urlsplit(s); q=parse_qs(u.query)
        if u.scheme=='vmess':
            d=json.loads(decode(s[8:].split('#')[0])); host=d['add']; port=int(d['port'])
            if not d.get('id'): return
        elif u.scheme=='ss':
            if not u.hostname or not u.port: return
            host,port=u.hostname,u.port
        else:
            host,port=u.hostname,u.port
            if not u.username: return
        if not host or not port: return
        if any(q.get(k,['0'])[0].lower() in ('1','true') for k in ('allowInsecure','insecure')): return
        if u.scheme in ('vless','trojan') and q.get('security',['none'])[0] not in ('tls','reality'): return
        if q.get('security')==['reality'] and not all(q.get(k) for k in ('pbk','sni')): return
        return host,port,u.scheme,q
    except Exception: return
def probe(item):
    s,info=item
    try:
        import ipaddress
        host,port,scheme,q=info
        ips=socket.getaddrinfo(host,port,type=socket.SOCK_STREAM)
        if not ips or any(not ipaddress.ip_address(x[4][0]).is_global for x in ips): return
        import time
        start=time.monotonic()
        with socket.create_connection((host,port),timeout=3): pass
        return s,info,time.monotonic()-start
    except Exception: return
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
    batches=list(ex.map(fetch,SOURCES))
evidence={}
for idx,batch in enumerate(batches):
    for link in batch:
        evidence.setdefault(link.split("#")[0],set()).add(idx)
seen=set(); items=[]
for batch in __import__("itertools").zip_longest(*batches):
    for s in filter(None,batch):
        key=s.split('#')[0]
        if key in seen: continue
        seen.add(key); info=inspect(s)
        if info: items.append((s,info))
with concurrent.futures.ThreadPoolExecutor(max_workers=32) as ex:
    good=[x for x in ex.map(probe,items[:1500]) if x]
def rank(x):
    s,(_,port,scheme,q),delay=x
    origins=evidence.get(s.split("#")[0],set())
    priority=0 if 10 in origins else 1 if origins & {0,1,2,7} else 2 if origins & {8,9,5,6,12} else 3
    return (priority,0 if scheme=='vless' and q.get('security')==['reality'] and q.get('type',['tcp'])[0] in ('tcp','raw') else 1 if scheme=='trojan' else 2,delay,port!=443)
good.sort(key=rank)
# Interleave distinct endpoints before expensive tests.
unique=[]; overflow=[]; endpoints=set()
for item in good:
    host=item[1][0].lower()
    if host in endpoints: overflow.append(item)
    else: endpoints.add(host); unique.append(item)
# Round-robin across source groups, keeping distinct hostnames first.
groups={}
for item in unique:
    origins=evidence.get(item[0].split('#')[0],set())
    source=10 if 10 in origins else min(origins) if origins else -1
    groups.setdefault(source,[]).append(item)
good=[]
while any(groups.values()):
    for source, group in groups.items():
        for _ in range(5 if source==10 else 1):
            if group: good.append(group.pop(0))
good+=overflow
def tunnel(item):
    import tempfile, subprocess, time, os
    link,(host,port,scheme,q),delay=item
    def v(k,default=''): return q.get(k,[default])[0]
    try:
        u=urlsplit(link)
        if scheme not in ('vless','trojan'): return
        transport=v('type','tcp')
        if transport not in ('tcp','raw','ws','grpc'): return
        security=v('security')
        if security not in ('tls','reality'): return
        stream={'network':transport,'security':security}
        if security=='reality':
            stream['realitySettings']={'serverName':v('sni'),'fingerprint':v('fp','chrome'),'publicKey':v('pbk'),'shortId':v('sid'),'spiderX':v('spx')}
        else:
            stream['tlsSettings']={'serverName':v('sni',host),'allowInsecure':False,'fingerprint':v('fp','chrome')}
            if v('alpn'): stream['tlsSettings']['alpn']=v('alpn').split(',')
        if transport=='ws': stream['wsSettings']={'path':v('path','/'),'headers':{'Host':v('host',host)}}
        if transport=='grpc': stream['grpcSettings']={'serviceName':v('serviceName')}
        from urllib.parse import unquote
        user={'id':unquote(u.username),'encryption':v('encryption','none')}
        if v('flow'): user['flow']=v('flow')
        settings={'vnext':[{'address':host,'port':port,'users':[user]}]} if scheme=='vless' else {'servers':[{'address':host,'port':port,'password':unquote(u.username)}]}
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0)); local=sock.getsockname()[1]
        cfg={'log':{'loglevel':'error'},'inbounds':[{'listen':'127.0.0.1','port':local,'protocol':'socks','settings':{'auth':'noauth','udp':False}}],'outbounds':[{'protocol':scheme,'settings':settings,'streamSettings':stream}]}
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'config.json'; p.write_text(json.dumps(cfg))
            proc=subprocess.Popen(['xray','run','-c',str(p)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            try:
                time.sleep(.6)
                results=[]
                for attempt in range(3):
                    if attempt: time.sleep(5)
                    url=('https://www.gstatic.com/generate_204','https://www.cloudflare.com/cdn-cgi/trace')[attempt%2]
                    out=subprocess.check_output(['curl','--silent','--show-error','--fail','--max-time','8','--socks5-hostname',f'127.0.0.1:{local}','-o',os.devnull,'-w','%{http_code} %{time_starttransfer}',url],stderr=subprocess.DEVNULL,text=True).split()
                    if out[0] not in ('200','204'): return
                    results.append(float(out[1]))
                for target in ('https://www.instagram.com/','https://www.youtube.com/generate_204','https://telegram.org/'):
                    out=subprocess.check_output(['curl','--silent','--show-error','--max-time','12','--max-filesize','2097152','--socks5-hostname',f'127.0.0.1:{local}','-o',os.devnull,'-w','%{http_code}',target],stderr=subprocess.DEVNULL,text=True)
                    if not out.startswith(('2','3')): return
                rates=[]
                for attempt in range(2):
                    out=subprocess.check_output(['curl','--silent','--show-error','--fail','--max-time','15','--socks5-hostname',f'127.0.0.1:{local}','-o',os.devnull,'-w','%{http_code} %{size_download} %{speed_download}','https://speed.cloudflare.com/__down?bytes=524288'],stderr=subprocess.DEVNULL,text=True).split()
                    if out[0]!='200' or float(out[1])<524288 or float(out[2])<125000: return
                    rates.append(float(out[2]))
                    if not attempt: time.sleep(10)
                return item,max(results),max(results)-min(results),min(rates)
            finally:
                proc.terminate()
                try: proc.wait(timeout=2)
                except subprocess.TimeoutExpired: proc.kill(); proc.wait()
    except Exception: return

candidates=good[:300]
with concurrent.futures.ThreadPoolExecutor(max_workers=32) as ex:
    tested=[x for x in ex.map(tunnel,candidates) if x]
import hashlib
history_path=Path('stability.json')
try: history=json.loads(history_path.read_text())
except Exception: history={}
def key(item): return hashlib.sha256(item[0].split('#')[0].encode()).hexdigest()
passed={key(x[0]) for x in tested}
for item in candidates:
    k=key(item)
    old=history.get(k,[])
    history[k]=(old+[int(k in passed)])[-24:]
def stability(x):
    h=history[key(x[0])]
    return (-(sum(h)+1)/(len(h)+2),-sum(h),-x[3],x[2],x[1],rank(x[0]))
tested.sort(key=stability)
history_path.write_text(json.dumps({k:v for k,v in history.items() if k in {key(i) for i in candidates}}))
good=[]
hosts=set()
for x in tested:
    item=x[0]; host=item[1][0].lower()
    if host in hosts: continue
    hosts.add(host); good.append(item)
print("HTTPS tunnel passes outside Iran:",len(good))
passed_rows=good[:]
# Include structurally valid TCP-reachable candidates after verified tunnels; these are not Iran-tested.
for item in candidates:
    if item[1][0].lower() not in hosts:
        hosts.add(item[1][0].lower()); good.append(item)
def tv_ok(x):
    return x[1][2] in ('vless','trojan','ss','vmess') and x[1][3].get('type',['tcp'])[0] in ('tcp','raw','ws','grpc')
tv=sorted(filter(tv_ok,good),key=lambda x:(key(x) not in passed, x[1][3].get('type',['tcp'])[0] not in ('tcp','raw'),rank(x)))
for name,rows,limit in [('v2box',good,100),('tizy',tv,50)]:
    p=Path(name+'.txt')
    if rows:
        p.write_text('\n'.join(x[0] for x in rows[:limit])+'\n')
    else:
        p.write_text('')
        print('No passing candidates:',name)
print('HTTPS tested outside Iran:',len(passed_rows),'TCP-only candidates:',len(good)-len(passed_rows),'No Iran test')
