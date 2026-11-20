"""Generate mint_r38g.py from mint_r38f.py (the r38g filing: package pkg_g, its tools, replay records and bindings)."""
import os
H = os.path.dirname(os.path.abspath(__file__))
s = open(os.path.join(H, 'mint_r38f.py'), encoding='utf8').read()
def R(a, b, n=1):
    global s
    assert s.count(a) == n, (a[:70], s.count(a)); s = s.replace(a, b)
R('"""mint_r38f.py - mint the sha256-r38 r38f evidence (Yukon mooselumph/hashsmash, track sha256-r38-exploratory).\n\nFork of mint_r38.py for the fifth filing.',
  '"""mint_r38g.py - mint the sha256-r38 r38g evidence (Yukon mooselumph/hashsmash, track sha256-r38-exploratory).\n\nFork of mint_r38f.py for the sixth filing (adds the r38g tools, the replay records, the offline bindings and the identity record).')
R('TAG = sys.argv[1] if len(sys.argv) > 1 else "r38f_v1"', 'TAG = sys.argv[1] if len(sys.argv) > 1 else "r38g_v1"')
R('    root = os.path.join(WAVE, "pkg_f", "candidate")', '    root = os.path.join(WAVE, "pkg_g", "candidate")')
R('    for rel in ("DECLARE_WINDOWS.md", "DECLARE_LONG_2026-10-25.md", "Q3_PLAN.md", "CRITIC_r38f.md", "RESULT.md"):',
  '    for rel in ("DECLARE_WINDOWS.md", "DECLARE_LONG_2026-10-25.md", "Q3_PLAN.md", "CRITIC_r38f.md", "CRITIC_r38g.md", "RESULT.md"):')
R('    cp(os.path.join(WAVE, "pkg_f", "docker_report_wsl_sha256-r38.json"), "docs/docker_report_sha256-r38.json")',
  '    cp(os.path.join(WAVE, "pkg_g", "docker_report_wsl_sha256-r38.json"), "docs/docker_report_sha256-r38.json")\n'
  '    cp(os.path.join(WAVE, "pkg_f", "docker_report_wsl_sha256-r38.json"), "docs/docker_report_r38f_sha256-r38.json")\n'
  '    for f in ("offline_bindings.json", "dependencies.json", "submission-note.md", "tokens.json"): cp(os.path.join(WAVE, "pkg_g", f), "docs/" + f)\n'
  '    cp(os.path.join(WAVE, "pkg_g", "work", "identity.json"), "docs/identity.json")\n'
  '    for sub in ("replay_final", "replay"):\n'
  '        for f in sorted(os.listdir(os.path.join(WAVE, "pkg_g", sub))):\n'
  '            if f.endswith(".json"): cp(os.path.join(WAVE, "pkg_g", sub, f), "runs/" + sub + "/" + f)\n'
  '    for f in sorted(os.listdir(os.path.join(WAVE, "pkg_g", "work"))):\n'
  '        if f.startswith("final_out_") and f.endswith(".json"): cp(os.path.join(WAVE, "pkg_g", "work", f), "runs/organizer_outputs/" + f)')
R('NEUTRAL_TOOLS = ["q3_run.sh", "q3_launch_O.sh", "f7g_long.sh", "q3mirror.py", "q3ref.py", "q3smc.py", "stat_bounds.py", "make_q3data.py", "fill_proof_f.py"]',
  'NEUTRAL_TOOLS = ["q3_run.sh", "q3_launch_O.sh", "f7g_long.sh", "q3mirror.py", "q3ref.py", "q3smc.py", "stat_bounds.py", "make_q3data.py", "fill_proof_f.py",\n'
  '                 "../pkg_g/tools/fill_proof_g.py", "../pkg_g/tools/fill_extra_g.py", "../pkg_g/tools/make_joint_g.py", "../pkg_g/tools/new_e.txt",\n'
  '                 "../pkg_g/tools/make_q3data_g.py", "../pkg_g/tools/replay_record.py", "../pkg_g/tools/replay_all.sh", "../pkg_g/tools/wsl_run_experiments.py",\n'
  '                 "../pkg_g/tools/mem_inventory_g.py", "../pkg_g/tools/make_manifest_g.py", "../pkg_g/tools/make_proof_template_g.py",\n'
  '                 "../pkg_g/tools/tpl_blocks_g.txt", "../pkg_g/tools/org_seeds.py", "../pkg_g/tools/mkreq.py", "../pkg_g/tools/check_g.sh"]')
R('        dst = os.path.join(IN, "tools", f); os.makedirs(os.path.dirname(dst), exist_ok=True); open(dst, "w", encoding="utf8", newline="\\n").write(t)\n        neut[f] =',
  '        f2 = f.replace("../pkg_g/tools/", "r38g/")\n'
  '        dst = os.path.join(IN, "tools", f2); os.makedirs(os.path.dirname(dst), exist_ok=True); open(dst, "w", encoding="utf8", newline="\\n").write(t)\n        neut[f2] =')
R('    B.ledger("r38f-package", "the r38f candidate package: claim, proof, manifests, the program and the deep-rate data program", pk); ledgers.append("r38f-package")',
  '    B.ledger("r38g-package", "the r38g candidate package: claim, proof, manifests, the program and the two evidence programs", pk); ledgers.append("r38g-package")')
R('    tok = json.load(open(os.path.join(WAVE, "pkg_f", "tokens.json")))', '    tok = json.load(open(os.path.join(WAVE, "pkg_g", "tokens.json")))')
R('"q3r_log2_charged": float(tok["Q3R"]), "leader": "newjordan 51613d1c 90.7352"})',
  '"q3r_log2_charged": float(tok["Q3R"]), "q3r_log2_measured_corroborating": float(tok["Q3RM"]), "f7_charged": float(tok["F7CH"]),\n'
  '                                     "offline_root": tok["OFFLINE_ROOT"], "leader": "newjordan 51613d1c 90.7352"})')
R('B.ledger(TAG + "-files", "declarations, the registered deep-rate plan, critic review, result, organizer Docker report, window and seed JSONs, tools, lever evidence", fks)',
  'B.ledger(TAG + "-files", "declarations, the registered deep-rate plan, critic reviews, result, organizer Docker reports (r38g and r38f), organizer outputs, replay records, offline bindings, identity record, window and seed JSONs, tools, lever evidence", fks)')
open(os.path.join(H, 'mint_r38g.py'), 'w', encoding='utf8', newline='\n').write(s)
print('ok')
