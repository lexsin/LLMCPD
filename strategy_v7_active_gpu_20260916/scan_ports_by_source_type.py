#!/usr/bin/env python3
"""Apply -Pn by enterprise size and original source record type."""
import argparse,csv,json,subprocess,sys
from pathlib import Path
COL_START="\u8d77\u59cbIP";COL_END="\u7ec8\u6b62IP";COL_IP="ip";THRESHOLD=50000
def read_rows(path):
    for encoding in ("utf-8-sig","gbk","utf-8"):
        try:
            with path.open(encoding=encoding,newline="") as handle:
                reader=csv.DictReader(handle);return list(reader),list(reader.fieldnames or [])
        except UnicodeDecodeError: pass
    raise ValueError("unsupported CSV encoding: %s"%path)
def write_rows(path,rows,fieldnames):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("w",encoding="utf-8-sig",newline="") as handle:
        writer=csv.DictWriter(handle,fieldnames=fieldnames,extrasaction="ignore");writer.writeheader();writer.writerows(rows)
def unique_ip_count(rows):
    return len({r.get(COL_IP,"").strip() for r in rows if r.get(COL_IP,"").strip()})
def explicit_single_ips(rows):
    return {r.get(COL_START,"").strip() for r in rows if r.get(COL_START,"").strip() and r.get(COL_START,"").strip()==r.get(COL_END,"").strip()}
def classify_rows(rows,source_rows):
    if unique_ip_count(rows)<THRESHOLD:return rows,[],"all_pn_below_50000"
    singles=explicit_single_ips(source_rows)
    return ([r for r in rows if r.get(COL_IP,"").strip() in singles],[r for r in rows if r.get(COL_IP,"").strip() not in singles],"single_source_pn_range_source_discovery")
def run_scanner(args,mode,rows,fields):
    if not rows:return None
    mode_dir=args.work_dir/mode;input_path=mode_dir/"input.csv";output_path=mode_dir/"scan_result.csv";write_rows(input_path,rows,fields)
    cmd=[sys.executable,str(args.scanner),"--input",str(input_path),"--output",str(output_path),"--cache",str(mode_dir/"port_cache.json"),"--checkpoint",str(mode_dir/"port_checkpoint.jsonl"),"--tmp-dir",str(mode_dir/"cache"),"--batch-size",str(args.batch_size),"--parallel-workers",str(args.parallel_workers),"--verify-workers",str(args.verify_workers),"--min-rate",str(args.min_rate),"--max-retries",str(args.max_retries),"--host-timeout",args.host_timeout,"--resume"]
    if mode=="host_discovery":cmd.append("--host-discovery")
    print("Running %s scan for %d rows"%(mode,len(rows)),flush=True);subprocess.run(cmd,check=True);return output_path
def merge_results(source_rows,source_fields,result_paths,output_path):
    by_ip={};result_fields=[]
    for path in result_paths:
        if path is None:continue
        rows,fields=read_rows(path)
        for field in fields:
            if field not in result_fields:result_fields.append(field)
        for row in rows:
            ip=row.get(COL_IP,"").strip()
            if ip:by_ip[ip]=row
    fields=source_fields+[f for f in result_fields if f not in source_fields];merged=[]
    for source in source_rows:
        row=dict(source);row.update(by_ip.get(source.get(COL_IP,"").strip(),{}));merged.append(row)
    temp=output_path.with_suffix(output_path.suffix+".tmp");write_rows(temp,merged,fields);temp.replace(output_path)
def parse_args():
    p=argparse.ArgumentParser()
    p.add_argument("--source",required=True,type=Path);p.add_argument("--input",required=True,type=Path);p.add_argument("--output",required=True,type=Path);p.add_argument("--work-dir",required=True,type=Path);p.add_argument("--scanner",required=True,type=Path)
    p.add_argument("--batch-size",type=int,default=500);p.add_argument("--parallel-workers",type=int,default=12);p.add_argument("--verify-workers",type=int,default=12);p.add_argument("--min-rate",default="3000");p.add_argument("--max-retries",default="1");p.add_argument("--host-timeout",default="120s");return p.parse_args()
def main():
    args=parse_args();rows,fields=read_rows(args.input);source_rows,_=read_rows(args.source);pn,discovery,policy=classify_rows(rows,source_rows);args.work_dir.mkdir(parents=True,exist_ok=True)
    summary={"policy":policy,"threshold":THRESHOLD,"total_unique_ips":unique_ip_count(rows),"explicit_single_source_ips":len(explicit_single_ips(source_rows)),"pn_unique_ips":unique_ip_count(pn),"host_discovery_unique_ips":unique_ip_count(discovery)}
    (args.work_dir/"mode_summary.json").write_text(json.dumps(summary,ensure_ascii=False,indent=2)+"\n",encoding="utf-8");print(json.dumps(summary,ensure_ascii=False),flush=True)
    merge_results(rows,fields,[run_scanner(args,"pn",pn,fields),run_scanner(args,"host_discovery",discovery,fields)],args.output)
if __name__=="__main__":main()
