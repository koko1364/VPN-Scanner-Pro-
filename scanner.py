import urllib.request, base64, json, re, concurrent.futures, socket
from urllib.parse import urlsplit, parse_qs
from pathlib import Path
SOURCES = [
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
for batch in batches:
    for s in batch:
        key=s.split('#')[0]
        if key in seen: continue
        seen.add(key); info=inspect(s)
        if info: items.append((s,info))
with concurrent.futures.ThreadPoolExecutor(max_workers=32) as ex:
    good=[x for x in ex.map(probe,items[:1500]) if x]
def rank(x):
    s,(_,port,scheme,q),delay=x
    origins=evidence.get(s.split("#")[0],set())
    priority=0 if 0 in origins else 1 if {1,2} <= origins else 2 if origins & {1,2} else 3
    return (priority,0 if scheme=='vless' and q.get('security')==['reality'] and q.get('type',['tcp'])[0] in ('tcp','raw') else 1 if scheme=='trojan' else 2,delay,port!=443)
good.sort(key=rank)
for name,rows in [('v2box',good),('tizy',[x for x in good if x[1][2] in ('vless','vmess','trojan','ss') and x[1][3].get('type',['tcp'])[0] in ('tcp','raw','ws','grpc')])]:
    p=Path(name+'.txt')
    if rows:
        p.write_text('\n'.join(x[0] for x in rows[:30])+'\n')
    elif not p.exists():
        p.write_text('')
    else:
        print('No candidates; retaining previous file:',name)
print('TCP reachable candidates only; no VPN tunnel or Iran test:',len(good))
