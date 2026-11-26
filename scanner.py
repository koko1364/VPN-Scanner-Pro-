import urllib.request, base64, json, re, concurrent.futures, socket
from urllib.parse import urlsplit, parse_qs
from pathlib import Path
SOURCES = [
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
        if q.get('allowInsecure',['0'])[0].lower() in ('1','true'): return
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
        with socket.create_connection((host,port),timeout=3): pass
        return s,info
    except Exception: return
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
    batches=list(ex.map(fetch,SOURCES))
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
    _,(_,port,scheme,q)=x
    return (0 if scheme=='vless' and q.get('security')==['reality'] and q.get('type',['tcp'])[0] in ('tcp','raw') else 1 if scheme=='trojan' else 2,port!=443)
good.sort(key=rank)
for name,rows in [('v2box',good),('tizy',[x for x in good if x[1][2] in ('vless','vmess','trojan','ss') and x[1][3].get('type',['tcp'])[0] in ('tcp','raw','ws','grpc')])]:
    p=Path(name+'.txt')
    p.write_text('\n'.join(x[0] for x in rows[:30])+'\n' if rows else '')
print('TCP reachable candidates only; no VPN tunnel or Iran test:',len(good))
