#!/usr/bin/env python3
from align_gpu_explanations import aligned_note, line_facts


line = (
    'vllm:cache_config_info{engine="0",gpu_memory_utilization="0.93",'
    'num_gpu_blocks="1107",num_gpu_blocks_override="None"} 1.0'
)
facts = line_facts([line])
assert "gpu_memory_utilization=0.93" in facts
assert "num_gpu_blocks=1107" in facts
assert not any("override" in fact for fact in facts)
note = aligned_note(
    "http://192.0.2.1:8000/metrics",
    (200, "text/plain", line.encode()),
    "old",
    [line],
)
assert "gpu_memory_utilization=0.93" in note
assert "num_gpu_blocks=1107" in note
print("align_gpu_explanations_tests=passed")
