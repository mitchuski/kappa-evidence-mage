"""ipfs_cid.py - re-derive a UnixFS CIDv1 (sha2-256, raw leaves) from file bytes; build(b, chunk, raw)."""
import hashlib,base64,sys,glob,os
def uv(n):
    o=b''
    while True:
        b=n&0x7f; n>>=7
        if n: o+=bytes([b|0x80])
        else: return o+bytes([b])
def fld(no,wt,payload):
    k=uv(no<<3|wt)
    return k+(uv(len(payload))+payload if wt==2 else uv(payload))
def unixfs(data=None,size=0,bs=()):
    m=fld(1,0,2)
    if data is not None and len(data)>0: m+=fld(2,2,data)
    m+=fld(3,0,size)
    for b in bs: m+=fld(4,0,b)
    return m
def pbnode(links,data):
    out=b''
    for h,ts in links: out+=fld(2,2,fld(1,2,h)+fld(2,2,b'')+fld(3,0,ts))
    return out+fld(1,2,data)
def cid(codec,b): return bytes([1,codec,0x12,0x20])+hashlib.sha256(b).digest()
def s(c): return 'b'+base64.b32encode(c).decode().lower().rstrip('=')
def build(b,chunk,raw):
    if len(b)<=chunk:
        if raw: return s(cid(0x55,b))
        return s(cid(0x70,pbnode([],unixfs(b,len(b)))))
    links=[];sizes=[]
    for i in range(0,len(b),chunk):
        c=b[i:i+chunk]
        if raw: links.append((cid(0x55,c),len(c)))
        else:
            n=pbnode([],unixfs(c,len(c))); links.append((cid(0x70,n),len(n)))
        sizes.append(len(c))
    return s(cid(0x70,pbnode(links,unixfs(None,len(b),sizes))))
