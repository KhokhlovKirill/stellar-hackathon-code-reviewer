"""Deterministic detectors (near-zero FP): secrets, Semgrep SAST, SCA.

These run regardless of LLM availability and are the safety net for the highest-
weight criteria (C3). Findings carry source=DETERMINISTIC, confidence ~0.98.
"""
