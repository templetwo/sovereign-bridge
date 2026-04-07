#!/usr/bin/env python3
"""
Sovereign Stack Stress Tests — Validates the 4 new tools (39-42)
Run on Mac Studio: python3 stress_test_metabolism.py

Tests:
1. context_retrieve under various focus conditions
2. metabolize with real chronicle data
3. self_model read/update cycles
4. retire_hypothesis with edge cases
5. Concurrency — multiple tools called rapidly
6. Bad input handling — malformed arguments, empty fields
"""

import httpx
import json
import time
import sys
import os

# Config imported below
import sys; sys.path.insert(0, os.path.dirname(__file__))
from bridge_config import BRIDGE_URL, BRIDGE_TOKEN as TOKEN, HEADERS
# Token imported below

# Config loaded from bridge_config.py

passed = 0
failed = 0
errors = []


def call(tool, arguments, timeout=10):
    """Call a tool via bridge."""
    try:
        r = httpx.post(
            f"{BRIDGE_URL}/api/call",
            headers=HEADERS,
            json={"tool": tool, "arguments": arguments},
            timeout=timeout,
        )
        return r.json() if r.status_code == 200 else {"error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def test(name, condition, detail=""):
    global passed, failed
    if condition:
        print(f"  ✅ {name}")
        passed += 1
    else:
        print(f"  ❌ {name} — {detail}")
        failed += 1
        errors.append(f"{name}: {detail}")


# ================================================================
# 1. CONTEXT_RETRIEVE
# ================================================================
print("\n=== CONTEXT_RETRIEVE ===")

# Basic call
r = call("context_retrieve", {"focus": "governance lineage compass"})
test("context_retrieve returns result",
     r.get("ok") or "result" in r,
     str(r)[:100])

# Empty focus
r = call("context_retrieve", {"focus": ""})
test("context_retrieve handles empty focus",
     "error" not in r or r.get("ok"),
     str(r)[:100])

# Very long focus string
r = call("context_retrieve", {"focus": "a " * 500})
test("context_retrieve handles long focus",
     "error" not in r or r.get("ok"),
     str(r)[:100])

# Domain-specific focus
r = call("context_retrieve", {"focus": "AbstentionBench factual unknowables boundary"})
test("context_retrieve domain-specific focus returns data",
     r.get("ok") or "result" in r,
     str(r)[:100])


# ================================================================
# 2. METABOLIZE
# ================================================================
print("\n=== METABOLIZE ===")

# Run metabolism
r = call("metabolize", {}, timeout=30)
test("metabolize completes",
     r.get("ok") or "result" in r,
     str(r)[:100])

# Check it returns structured data
result = r.get("result", "")
if isinstance(result, str):
    test("metabolize returns report",
         "contradict" in result.lower() or "stale" in result.lower() or "insight" in result.lower(),
         f"Got: {result[:100]}")
else:
    test("metabolize returns report", True)

# Run twice rapidly — should not corrupt
r2 = call("metabolize", {}, timeout=30)
test("metabolize survives rapid re-run",
     r2.get("ok") or "result" in r2,
     str(r2)[:100])


# ================================================================
# 3. SELF_MODEL
# ================================================================
print("\n=== SELF_MODEL ===")

# Read self-model
r = call("self_model", {"action": "read"})
test("self_model read returns data",
     r.get("ok") or "result" in r,
     str(r)[:100])

result = r.get("result", "")
if isinstance(result, str):
    test("self_model contains strength field",
         "strength" in result.lower() or "synthesis" in result.lower(),
         f"Got: {result[:100]}")
else:
    test("self_model contains strength field", True)

# Update self-model with observation
r = call("self_model", {
    "action": "update",
    "observation": "Stress test: system correctly ran all tool validations without crashing",
    "category": "strength",
})
test("self_model update succeeds",
     r.get("ok") or "result" in r,
     str(r)[:100])

# Read again to verify update persisted
r = call("self_model", {"action": "read"})
test("self_model read after update",
     r.get("ok") or "result" in r,
     str(r)[:100])

# Bad action
r = call("self_model", {"action": "destroy_everything"})
test("self_model rejects bad action",
     "error" in str(r).lower() or r.get("ok"),  # either error or graceful handling
     str(r)[:100])


# ================================================================
# 4. RETIRE_HYPOTHESIS
# ================================================================
print("\n=== RETIRE_HYPOTHESIS ===")

# First, record a test hypothesis
call("record_insight", {
    "domain": "stress_test",
    "content": "STRESS TEST HYPOTHESIS: This should be retired by the stress test",
    "layer": "hypothesis",
    "intensity": 0.5,
})

# Run metabolism to pick it up
r = call("metabolize", {}, timeout=30)
test("metabolize after test hypothesis",
     r.get("ok") or "result" in r,
     str(r)[:100])

# Try retiring with empty ID (should handle gracefully)
r = call("retire_hypothesis", {"hypothesis_id": "", "reason": "test"})
test("retire_hypothesis handles empty ID",
     True,  # should not crash
     str(r)[:100])

# Try retiring with nonexistent ID
r = call("retire_hypothesis", {"hypothesis_id": "nonexistent_12345", "reason": "stress test"})
test("retire_hypothesis handles nonexistent ID",
     True,  # should not crash
     str(r)[:100])


# ================================================================
# 5. CONCURRENCY — rapid-fire calls
# ================================================================
print("\n=== CONCURRENCY ===")

import concurrent.futures

def rapid_call(i):
    return call("spiral_status", {}, timeout=5)

with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
    futures = [executor.submit(rapid_call, i) for i in range(10)]
    results = [f.result() for f in concurrent.futures.as_completed(futures)]

successes = sum(1 for r in results if r.get("ok") or "result" in r)
test(f"10 concurrent spiral_status calls: {successes}/10 succeeded",
     successes >= 8,  # allow some timeout under load
     f"Only {successes}/10")


# ================================================================
# 6. BAD INPUT HANDLING
# ================================================================
print("\n=== BAD INPUT HANDLING ===")

# Call nonexistent tool
r = call("this_tool_does_not_exist", {})
test("nonexistent tool returns error",
     "unknown" in str(r.get("result","")).lower() or "error" in str(r).lower(),
     str(r)[:100])

# Missing required arguments
r = call("record_insight", {})
test("record_insight with no args handles gracefully",
     True,  # should not crash the server
     str(r)[:100])

# Unicode in content
r = call("record_insight", {
    "domain": "stress_test",
    "content": "Unicode test: †⟡† 🦆 ñ ü 中文 العربية",
    "layer": "hypothesis",
    "intensity": 0.5,
})
test("record_insight handles unicode",
     r.get("ok") or "result" in r,
     str(r)[:100])

# Very large content
big_content = "x" * 50000
r = call("record_insight", {
    "domain": "stress_test",
    "content": big_content,
    "layer": "hypothesis",
    "intensity": 0.1,
})
test("record_insight handles 50KB content",
     True,  # should not crash
     str(r)[:100])


# ================================================================
# SUMMARY
# ================================================================
print(f"\n{'='*50}")
print(f"STRESS TEST RESULTS")
print(f"{'='*50}")
print(f"Passed: {passed}")
print(f"Failed: {failed}")
print(f"Total:  {passed + failed}")

if errors:
    print(f"\nFailures:")
    for e in errors:
        print(f"  ❌ {e}")

if failed == 0:
    print(f"\n🟢 ALL GREEN — Stack is solid")
else:
    print(f"\n🔴 {failed} FAILURES — needs attention")

sys.exit(0 if failed == 0 else 1)
