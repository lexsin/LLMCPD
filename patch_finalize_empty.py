from pathlib import Path


path = Path("finalize_llm_results.py")
text = path.read_text(encoding="utf-8")
old = """def write_result(df: pd.DataFrame, output: Path, reported_single_ips: set[str]) -> dict:
    normalized = transform(df, reported_single_ips)
    bucket_items = [
"""
new = """def write_result(df: pd.DataFrame, output: Path, reported_single_ips: set[str]) -> dict:
    normalized = transform(df, reported_single_ips)
    if normalized.empty:
        normalized = pd.DataFrame(columns=OUT_COLUMNS + ["_gpu_likelihood", "_service_type"])
    bucket_items = [
"""
if new in text:
    print("empty-result guard already present")
elif old in text:
    path.write_text(text.replace(old, new), encoding="utf-8")
    print("patched empty-result guard")
else:
    raise SystemExit("target text not found")
