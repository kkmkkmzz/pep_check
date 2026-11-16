import json,collections,sys
def P(s):
    c=collections.Counter()
    if s:
        for kv in s.split(","):
            a,b=kv.split(":");c[int(a)]+=int(b)
    return c
def q(c,p):
    xs=sorted(c.elements());
    if not xs:return None
    k=(len(xs)-1)*p;f=int(k);cc=min(f+1,len(xs)-1);return xs[f]+(xs[cc]-xs[f])*(k-f)
def S(c):
    xs=list(c.elements())
    return {"n":len(xs),"min":min(xs),"p50":q(c,.5),"p95":q(c,.95),"p99":q(c,.99),"max":max(xs)}
out={}
for name,f in [("ap-northeast-2","seoul_batches.jsonl"),("us-east-1","virginia_batches.jsonl")]:
    B=[json.loads(l) for l in open(f)]
    on=collections.Counter();oo=collections.Counter();rd=collections.Counter();st=collections.Counter();sti=collections.Counter();hr=collections.defaultdict(collections.Counter)
    nk=ngz=nobj=nrec=0;bad=[]
    for i,b in enumerate(B):
        a,o,r=P(b["on"]),P(b["oo"]),P(b["rd"])
        hs=sum(sum(P(v).values()) for v in b["hr"].values())
        if not(sum(a.values())==b["nobj"]==sum(o.values())==hs and sum(r.values())==b["nrec"]==sum(b.get("st_in",{}).values())): bad.append(i+1)
        on+=a;oo+=o;rd+=r;st.update(b["st"]);sti.update(b["st_in"])
        for h,v in b["hr"].items():hr[int(h)]+=P(v)
        nk+=b["nk"];ngz+=b["ngz"];nobj+=b["nobj"];nrec+=b["nrec"]
    keys=[b["lastfull"] for b in B]
    out[name]={"batches":len(B),"consistency_fail_batches":bad,"keys_scanned":nk,"gz_objects_scanned":ngz,
      "objects_with_in_window_records":nobj,"records":nrec,"log_status_all_scanned":dict(st),"log_status_in_window":dict(sti),
      "object_newest_record_delay_s":S(on),"object_oldest_record_delay_s":S(oo),"record_delay_s":S(rd),
      "hourly_p50_newest_kst":{h:q(hr[h],.5) for h in sorted(hr)},"hourly_n":{h:sum(hr[h].values()) for h in sorted(hr)},
      "share_over_600s_records":sum(v for k,v in rd.items() if k>600)/nrec,
      "share_over_600s_objects_newest":sum(v for k,v in on.items() if k>600)/nobj,
      "share_over_600s_objects_oldest":sum(v for k,v in oo.items() if k>600)/nobj,
      "first_last_key":[keys[0],keys[-1]]}
json.dump(out,open("a2_result_72h.json","w"),indent=1,ensure_ascii=False)
print(json.dumps(out,indent=1))
