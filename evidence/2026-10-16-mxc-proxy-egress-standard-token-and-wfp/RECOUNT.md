# Re-count of the figures in README.md, after sanitising

`recount.py` reads the run records (not `batch-summary.json`, whose verdicts it prints beside them), the launcher logs and, for the WFP batch, the `*-filters.xml` dumps (it parses each dump and compares filter keys inside one folder), and prints `name = value` figures. It was run over the raw folder of each batch and over the sanitised folder here, and the two outputs compared. The raw folder's omitted files (state dumps, `staging/cfg`, `staging/payload`) are not read. Filter keys differ between a raw and a sanitised folder (the sanitiser renames them), so between the two only counts and shapes are compared; set equality of keys (before and after) is computed inside each folder.

    python recount.py <raw-folder> <sanitised-folder>      # exit 1 on any difference

| Batch | Figures (raw / sanitised) | Differences | Exit |
|---|---|---|---|
| `runs/run-20261016-1/` | 70 / 70 | 0 | 0 |
| `runs/run-20261016-2/` | 99 / 99 | 0 | 0 |

The figures below are the sanitised folder's (identical to the raw folder's, per the table). Per-run lists are in run order r1, r2, r3 of the arm.

## runs/run-20261016-1/

```
run_records = 6
control.b5a.connected = True
control.b5b.connected = True
control.b5c.connected = True
control.judgement = {"b5a": true, "b5b": true, "b5c": true, "ok": true, "reasons": []}
summary.controls_ok = True
summary.A/A1.verdict = HOLD
summary.A/A1.runs = 3
summary.B/B1.verdict = HOLD
summary.B/B1.runs = 3
header.token_mode = standard
header.unreadable_under_this_token = ["wfp_mxc_filters"]
A.runs = 3
A.dry_run_rc0 = 3
A.dry_run_stderr_empty = 3
A.launch_exit0 = 3
A.b2_container_200 = 9
A.b2_proxy_log_forwarded = 9
A.b2_second_listener_marker = 9
A.b3_refused_10013 = 3
A.b4i_refused_10013 = 3
A.b4ii_refused_10013 = 3
A.b3_listener_hits = 0
A.unfenced_pre.c_connected = 3
A.unfenced_pre.gw_connected = 3
A.unfenced_post.c_connected = 3
A.unfenced_post.gw_connected = 3
A.state_changed_runs = 0
A.verdict_HOLD = 3
A.launch_wall_secs = 0.880 / 0.617 / 0.475
A.container_is_appcontainer = 3
A.container_integrity_low_S-1-16-4096 = 3
A.container_elevated_true = 0
A.launcher_token_mode_standard = 3
A.launcher_integrity = S-1-16-8192
A.bitdefender_processes = 16,16,16
A.logs = 3
A.log_psec_1_1_432_bytes = 3
A.log_firewall_rules_created_0 = 3
A.log_firewall_applied_false = 3
A.log_enforcement_mode_capabilities = 3
B.runs = 3
B.dry_run_rc0 = 3
B.dry_run_stderr_empty = 3
B.launch_exit0 = 3
B.b2_container_200 = 9
B.b2_proxy_log_forwarded = 9
B.b2_second_listener_marker = 9
B.b3_refused_10013 = 3
B.b4i_refused_10013 = 3
B.b4ii_refused_10013 = 3
B.b3_listener_hits = 0
B.unfenced_pre.c_connected = 3
B.unfenced_pre.gw_connected = 3
B.unfenced_post.c_connected = 3
B.unfenced_post.gw_connected = 3
B.state_changed_runs = 0
B.verdict_HOLD = 3
B.launch_wall_secs = 0.561 / 0.572 / 0.481
B.container_is_appcontainer = 3
B.container_integrity_low_S-1-16-4096 = 3
B.container_elevated_true = 0
B.launcher_token_mode_standard = 3
B.launcher_integrity = S-1-16-8192
B.bitdefender_processes = 16,16,16
B.logs = 3
B.log_psec_1_1_432_bytes = 3
B.log_firewall_rules_created_0 = 3
B.log_firewall_applied_false = 3
B.log_enforcement_mode_capabilities = 3
```

## runs/run-20261016-2/

```
run_records = 6
control.b5a.connected = True
control.b5b.connected = True
control.b5c.connected = True
control.judgement = {"b5a": true, "b5b": true, "b5c": true, "ok": true, "reasons": []}
summary.controls_ok = True
summary.A/A1.verdict = HOLD
summary.A/A1.runs = 3
summary.B/B1.verdict = HOLD
summary.B/B1.runs = 3
header.token_mode = elevated
header.unreadable_under_this_token = []
A.runs = 3
A.dry_run_rc0 = 3
A.dry_run_stderr_empty = 3
A.launch_exit0 = 3
A.b2_container_200 = 9
A.b2_proxy_log_forwarded = 9
A.b2_second_listener_marker = 9
A.b3_refused_10013 = 3
A.b4i_refused_10013 = 3
A.b4ii_refused_10013 = 3
A.b3_listener_hits = 0
A.unfenced_pre.c_connected = 3
A.unfenced_pre.gw_connected = 3
A.unfenced_post.c_connected = 3
A.unfenced_post.gw_connected = 3
A.state_changed_runs = 0
A.verdict_HOLD = 3
A.launch_wall_secs = 2.116 / 1.978 / 1.808
A.container_is_appcontainer = 3
A.container_integrity_low_S-1-16-4096 = 3
A.container_elevated_true = 3
A.launcher_token_mode_standard = 0
A.launcher_integrity = S-1-16-12288
A.bitdefender_processes = 16,16,16
A.logs = 3
A.log_psec_1_1_432_bytes = 3
A.log_firewall_rules_created_0 = 3
A.log_firewall_applied_false = 3
A.log_enforcement_mode_capabilities = 3
A.wfp.capture_during_container_alive = 3
A.wfp.record_counts_before/during/after = 1008/1016/1008 | 1008/1016/1008 | 1008/1016/1008
A.wfp.record_delta_count = 8,8,8
A.xml.filters_before/during/after = 1008/1016/1008 | 1008/1016/1008 | 1008/1016/1008
A.xml.new_during_not_in_before = 8,8,8
A.xml.after_keys_equal_before_keys = 3
A.xml.new_filter_names = MXC-Loopbackx2;Sandbox.{GUID}x2;Tessera Sandbox Filterx4 | MXC-Loopbackx2;Sandbox.{GUID}x2;Tessera Sandbox Filterx4 | MXC-Loopbackx2;Sandbox.{GUID}x2;Tessera Sandbox Filterx4
A.xml.new_filters_keyed_to_run_package_sid = 6,6,6
A.xml.new_filters_PERMIT = 6,6,6
A.xml.new_filters_BLOCK = 2,2,2
B.runs = 3
B.dry_run_rc0 = 3
B.dry_run_stderr_empty = 3
B.launch_exit0 = 3
B.b2_container_200 = 9
B.b2_proxy_log_forwarded = 9
B.b2_second_listener_marker = 9
B.b3_refused_10013 = 3
B.b4i_refused_10013 = 3
B.b4ii_refused_10013 = 3
B.b3_listener_hits = 0
B.unfenced_pre.c_connected = 3
B.unfenced_pre.gw_connected = 3
B.unfenced_post.c_connected = 3
B.unfenced_post.gw_connected = 3
B.state_changed_runs = 0
B.verdict_HOLD = 3
B.launch_wall_secs = 1.836 / 2.102 / 1.827
B.container_is_appcontainer = 3
B.container_integrity_low_S-1-16-4096 = 3
B.container_elevated_true = 3
B.launcher_token_mode_standard = 0
B.launcher_integrity = S-1-16-12288
B.bitdefender_processes = 16,16,16
B.logs = 3
B.log_psec_1_1_432_bytes = 3
B.log_firewall_rules_created_0 = 3
B.log_firewall_applied_false = 3
B.log_enforcement_mode_capabilities = 3
B.wfp.capture_during_container_alive = 3
B.wfp.record_counts_before/during/after = 1008/1016/1008 | 1008/1016/1008 | 1008/1016/1008
B.wfp.record_delta_count = 8,8,8
B.xml.filters_before/during/after = 1008/1016/1008 | 1008/1016/1008 | 1008/1016/1008
B.xml.new_during_not_in_before = 8,8,8
B.xml.after_keys_equal_before_keys = 3
B.xml.new_filter_names = MXC-Loopbackx2;Sandbox.{GUID}x2;Tessera Sandbox Filterx4 | MXC-Loopbackx2;Sandbox.{GUID}x2;Tessera Sandbox Filterx4 | MXC-Loopbackx2;Sandbox.{GUID}x2;Tessera Sandbox Filterx4
B.xml.new_filters_keyed_to_run_package_sid = 6,6,6
B.xml.new_filters_PERMIT = 6,6,6
B.xml.new_filters_BLOCK = 2,2,2
summary.variant4_wfp.verdict = FILTERS-PRESENT
summary.variant4_wfp.runs = 6
summary.variant4_wfp.FILTERS-PRESENT_readings = 6
wfp_control.created = True
wfp_control.removed_verified = True
wfp_control.absent_after_removal = True
wfp_control.ok = False
wfp_control.found_filters = 0
wfp_dump_files.filters = 20
```

The README states these figures in its tables and text: dry-run and launch counts, B2, B3, B4 results and listener hits, unconfined connects, state-change counts, verdicts, launch wall times, container token fields, launcher-log PSEC and `firewall_rules_created` lines, and for the WFP batch the filter counts before, during and after, the eight new filters per launch with their names, their action split (6 PERMIT, 2 BLOCK) and the six keyed to the run's package SID, the key-set equality of before and after, the capture-alive count, the FILTERS-PRESENT readings and the positive-control fields.
