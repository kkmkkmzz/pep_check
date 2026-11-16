R = "ap-northeast-2"
async def ec2(op, **p): return await call_boto3(service_name="ec2", operation_name=op, region_name=R, params=p)
SG = {"trk": "<SG_01>", "unt": "<SG_02>", "iso": "<SG_03>"}
X = {"t3-Xt": ("<ENI_01>", "trk", "10.20.1.11", "<IPV6PREFIX>:a901::11"),
     "t3-Xu": ("<ENI_02>", "unt", "10.20.1.12", "<IPV6PREFIX>:a901::12"),
     "t3-X6": ("<ENI_03>", "trk", "10.20.1.13", "<IPV6PREFIX>:a901::13"),
     "g-Xt": ("<ENI_06>", "trk", "10.20.1.21", "<IPV6PREFIX>:a901::21"),
     "g-Xu": ("<ENI_07>", "unt", "10.20.1.22", "<IPV6PREFIX>:a901::22"),
     "g-X6": ("<ENI_08>", "trk", "10.20.1.23", "<IPV6PREFIX>:a901::23")}
IDS = {"t3-Xt": "<INSTANCE_01>", "t3-Xu": "<INSTANCE_02>", "t3-X6": "<INSTANCE_03>", "t3-Ps": "<INSTANCE_04>", "t3-Po": "<INSTANCE_05>", "g-Xt": "<INSTANCE_06>", "g-Xu": "<INSTANCE_07>", "g-X6": "<INSTANCE_08>", "g-Ps": "<INSTANCE_09>", "g-Po": "<INSTANCE_10>"}
NACL = "<ACL_01>"; RT = "<RTB_01>"; BH = "<ENI_11>"; SUBB6 = "<IPV6PREFIX>:a902::/64"
BUCKET = "<BUCKET_01>"
PATHS = {"other": "<NIPATH_01>", "same": "<NIPATH_02>"}
log = {"act": ACT, "rep": REP, "t_start": time.time()}

async def tag(v):
    await ec2("CreateTags", Resources=list(IDS.values()), Tags=[{"Key": "ctl", "Value": v}]); log["t_tag"] = time.time(); log["tag"] = v

async def nacl_entries():
    n = (await ec2("DescribeNetworkAcls", NetworkAclIds=[NACL]))["NetworkAcls"][0]
    return [(e["RuleNumber"], e["Egress"]) for e in n["Entries"] if e["RuleNumber"] < 100]

async def del_nacl():
    ents = await nacl_entries()
    await asyncio.gather(*[ec2("DeleteNetworkAclEntry", NetworkAclId=NACL, RuleNumber=r, Egress=eg) for r, eg in ents])
    return len(ents)

async def del_routes():
    rt = (await ec2("DescribeRouteTables", RouteTableIds=[RT]))["RouteTables"][0]["Routes"]
    k = 0
    for r in rt:
        if r.get("NetworkInterfaceId") == BH:
            if r.get("DestinationCidrBlock"): await ec2("DeleteRoute", RouteTableId=RT, DestinationCidrBlock=r["DestinationCidrBlock"])
            else: await ec2("DeleteRoute", RouteTableId=RT, DestinationIpv6CidrBlock=r["DestinationIpv6CidrBlock"])
            k += 1
    return k

if ACT == "base":
    log["t_change0"] = time.time()
    await asyncio.gather(*[ec2("ModifyNetworkInterfaceAttribute", NetworkInterfaceId=v[0], Groups=[SG[v[1]]]) for v in X.values()])
    log["nacl_removed"] = await del_nacl(); log["routes_removed"] = await del_routes()
    log["t_change1"] = time.time()
    await asyncio.sleep(3)
    await tag("base-%d" % REP)
elif ACT == "sg":
    log["t_change0"] = time.time()
    await asyncio.gather(*[ec2("ModifyNetworkInterfaceAttribute", NetworkInterfaceId=v[0], Groups=[SG["iso"]]) for v in X.values()])
    log["t_change1"] = time.time()
    await tag("sg-%d" % REP)
elif ACT == "nacl":
    calls = []
    for k, v in enumerate(X.values()):
        for eg in (False, True):
            calls.append(ec2("CreateNetworkAclEntry", NetworkAclId=NACL, RuleNumber=10 + k, Protocol="-1", RuleAction="deny", Egress=eg, CidrBlock=v[2] + "/32"))
            calls.append(ec2("CreateNetworkAclEntry", NetworkAclId=NACL, RuleNumber=30 + k, Protocol="-1", RuleAction="deny", Egress=eg, Ipv6CidrBlock=v[3] + "/128"))
    log["t_change0"] = time.time()
    await asyncio.gather(*calls)
    log["t_change1"] = time.time()
    await tag("nacl-%d" % REP)
elif ACT == "rev":
    log["t_change0"] = time.time()
    log["nacl_removed"] = await del_nacl()
    log["t_change1"] = time.time()
    await tag("rev-%d" % REP)
elif ACT == "route":
    log["t_change0"] = time.time()
    await asyncio.gather(ec2("CreateRoute", RouteTableId=RT, DestinationCidrBlock="10.20.2.0/24", NetworkInterfaceId=BH),
                         ec2("CreateRoute", RouteTableId=RT, DestinationIpv6CidrBlock=SUBB6, NetworkInterfaceId=BH))
    log["t_change1"] = time.time()
    await tag("route-%d" % REP)

if RA:
    ra = await asyncio.gather(*[ec2("StartNetworkInsightsAnalysis", NetworkInsightsPathId=p, TagSpecifications=[{"ResourceType": "network-insights-analysis", "Tags": [{"Key": "Project", "Value": "pep-a1"}, {"Key": "Phase", "Value": "%s-%d-%s" % (ACT, REP, k)}]}]) for k, p in PATHS.items()])
    log["ra"] = {k: r["NetworkInsightsAnalysis"]["NetworkInsightsAnalysisId"] for k, r in zip(PATHS, ra)}

if COLLECT:
    async def grab(n, i):
        r = await ec2("GetConsoleOutput", InstanceId=i, Latest=True)
        t = r.get("Output", "") or ""
        await call_boto3(service_name="s3", operation_name="PutObject", params={"Bucket": BUCKET, "Key": "a1/console/%s/%d.txt" % (n, int(time.time())), "Body": t})
        seqs = [int(l.split("|")[3]) for l in t.splitlines() if l.startswith("D|")]
        errs = [l[:120] for l in t.splitlines() if l.startswith("E|")]
        return n, {"len": len(t), "seq": [min(seqs), max(seqs)] if seqs else None, "err": errs[-2:]}
    log["console"] = dict(await asyncio.gather(*[grab(n, i) for n, i in IDS.items()]))

await call_boto3(service_name="s3", operation_name="PutObject", params={"Bucket": BUCKET, "Key": "a1/phases/%d-%s-%d.json" % (REP, ACT, int(log["t_start"])), "Body": json.dumps(log)})
result = log
result
