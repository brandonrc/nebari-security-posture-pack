"""SCAP scanner (DESIGN §14): OpenSCAP product / OS STIG evaluation inside container images.

rootfs (OCI layers -> directory), detect (os-release / products -> candidate benchmarks),
content (datastream catalogue), oscap (adapter + ARF parser), scoring (STIG score), stage
(worker stage), models (tables, migration 0007).
"""
