# hids.behavioral — Phase 1: Behavioral Anomaly Detection Foundation
#
# Modules:
#   collector       — continuous process data collection via psutil
#   features        — behavioral feature extraction from raw process data
#   baseline        — normal-behavior baseline builder and persistence
#   scorer          — statistical anomaly scoring engine
#   behavioral_engine — top-level orchestrator (replaces filename-based detection)
