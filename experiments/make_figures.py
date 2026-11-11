"""Generate publication-quality figures from measured CSVs in results/."""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

from agent_cti.config import find_repo_root


def make_all_figures(results_dir: Path | None = None) -> list[Path]:
    repo = find_repo_root()
    res_dir = results_dir or (repo / "results")
    fig_dir = res_dir / "figures"
    fig_dir.mkdir(parents=True, exist_ok=True)

    sns.set_theme(style="whitegrid", context="paper", font_scale=1.1)
    ablation = pd.read_csv(res_dir / "summary_ablation.csv")
    per_threat = pd.read_csv(res_dir / "per_threat_asr.csv")
    load_df = pd.read_csv(res_dir / "load_scaling_hitl_vs_auto.csv")
    raw_sto = pd.read_csv(res_dir / "raw_trials_stochastic.csv")
    holdout = pd.read_csv(res_dir / "holdout_ablation.csv")
    budget_df = pd.read_csv(res_dir / "pillar1_budget_ablation.csv")

    generated: list[Path] = []

    # --- Figure 1: Ablation Overview (ASR, Block/Detect, Benign Success with 95% CIs) ---
    fig, ax = plt.subplots(figsize=(9.5, 4.8))
    x = np.arange(len(ablation))
    w = 0.26
    ax.bar(x - w, ablation["asr_mean_pct"], yerr=ablation["asr_ci95_pct"], width=w, capsize=3, label="Attack Success Rate (%)", color="#d62728")
    ax.bar(x, ablation["block_detect_mean_pct"], yerr=ablation["block_detect_ci95_pct"], width=w, capsize=3, label="Block / Detect Rate (%)", color="#1f77b4")
    ax.bar(x + w, ablation["benign_success_mean_pct"], yerr=ablation["benign_success_ci95_pct"], width=w, capsize=3, label="Benign Task Success (%)", color="#2ca02c")
    cond_labels = ["C0\nUndefended", "C1\nSim. HITL", "C2\nGuardrails", "C3\nRuntime", "C4\nGuard+RT", "C5\nFull Loop"]
    ax.set_xticks(x)
    ax.set_xticklabels(cond_labels)
    ax.set_ylim(0, 112)
    ax.set_ylabel("Percentage (%)")
    ax.set_title("Defense Effectiveness & Benign Utility Across Conditions (5 Seeds, 95% CI)", pad=28)
    ax.legend(loc="lower center", bbox_to_anchor=(0.5, 1.01), ncol=3, frameon=True)
    for i, r in ablation.iterrows():
        ax.text(i - w, r["asr_mean_pct"] + r["asr_ci95_pct"] + 1.5, f"{r['asr_mean_pct']:.1f}", ha="center", fontsize=8)
    fig.tight_layout()
    p1 = fig_dir / "fig1_ablation_overview.png"
    fig.savefig(p1, dpi=300, bbox_inches="tight")
    plt.close(fig)
    generated.append(p1)

    # --- Figure 2: Per-Threat ASR Heatmap (T01..T13 x C0..C5) ---
    piv = per_threat.pivot(index="threat_id", columns="condition", values="asr_mean_pct")[["C0", "C1", "C2", "C3", "C4", "C5"]]
    piv.index = [t.replace("_", " ", 1).replace("_", " ")[:32] for t in piv.index]
    fig, ax = plt.subplots(figsize=(9.5, 6.2))
    sns.heatmap(piv, annot=True, fmt=".1f", cmap="YlOrRd", vmin=0.0, vmax=100.0, linewidths=0.5, cbar_kws={"label": "Attack Success Rate (%)"}, ax=ax)
    ax.set_title("Attack Success Rate (%) by Threat Class Across Defense Conditions")
    ax.set_xlabel("Defense Condition")
    ax.set_ylabel("Threat Class (Pillar 1 Catalog)")
    fig.tight_layout()
    p2 = fig_dir / "fig2_threat_heatmap.png"
    fig.savefig(p2, dpi=300)
    plt.close(fig)
    generated.append(p2)

    # --- Figure 3: Simulated HITL vs Automated Load Scaling ---
    fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(15.0, 4.5))
    palette = {
        "Simulated HITL (1 reviewer)": "#d62728",
        "Simulated HITL (3 reviewers)": "#ff7f0e",
        "Automated C5 (Sandboxed)": "#1f77b4",
        "Automated C5 (In-Process)": "#2ca02c",
    }
    for sys_name, grp in load_df.groupby("system"):
        grp = grp.sort_values("arrival_rate_rpm")
        col = palette.get(sys_name, None)
        ax1.plot(grp["arrival_rate_rpm"], grp["effective_throughput_rpm"], marker="o", linewidth=2, label=sys_name, color=col)
        ax2.plot(grp["arrival_rate_rpm"], grp["p95_latency_ms"], marker="s", linewidth=2, label=sys_name, color=col)
        fail_rate = grp["drop_timeout_pct"] + grp["attack_miss_pct"]
        ax3.plot(grp["arrival_rate_rpm"], fail_rate, marker="^", linewidth=2, label=sys_name, color=col)

    ax1.set_xscale("log")
    ax1.set_yscale("log")
    ax1.set_xlabel("Incoming Request Rate (req/min)")
    ax1.set_ylabel("Effective Throughput (req/min)")
    ax1.set_title("(a) Throughput Capacity")
    ax1.legend(fontsize=8, loc="upper left")

    ax2.set_xscale("log")
    ax2.set_yscale("log")
    ax2.set_xlabel("Incoming Request Rate (req/min)")
    ax2.set_ylabel("p95 Decision Latency (ms, log)")
    ax2.set_title("(b) Tail Latency Under Load")
    ax2.legend(fontsize=8, loc="upper left")

    ax3.set_xscale("log")
    ax3.set_xlabel("Incoming Request Rate (req/min)")
    ax3.set_ylabel("Dropped/Timed-Out + Fatigue-Missed (%)")
    ax3.set_title("(c) Human Oversight Failure Under Load")
    ax3.legend(fontsize=8, loc="upper left")
    fig.suptitle("Simulated HITL Queue & Fatigue Collapse vs. Automated Continuous Defense (C5)", y=1.02)
    fig.tight_layout()
    p3 = fig_dir / "fig3_hitl_vs_automated_scaling.png"
    fig.savefig(p3, dpi=300, bbox_inches="tight")
    plt.close(fig)
    generated.append(p3)

    # --- Figure 4: Latency Overhead & Runtime Containment Timing ---
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11.2, 4.5))
    sub_auto = ablation[ablation["condition"].isin(["C0", "C2", "C3", "C4", "C5"])]
    xa = np.arange(len(sub_auto))
    ax1.bar(xa - 0.18, sub_auto["step_latency_p50_ms"], width=0.35, label="p50 Step Latency (ms)", color="#1f77b4")
    ax1.bar(xa + 0.18, sub_auto["step_latency_p95_ms"], width=0.35, label="p95 Step Latency (ms)", color="#ff7f0e")
    for idx_b, (_, row_b) in enumerate(sub_auto.iterrows()):
        ax1.text(idx_b - 0.18, row_b["step_latency_p50_ms"] + 1.5, f"{row_b['step_latency_p50_ms']:.1f}", ha="center", fontsize=8)
        ax1.text(idx_b + 0.18, row_b["step_latency_p95_ms"] + 1.5, f"{row_b['step_latency_p95_ms']:.1f}", ha="center", fontsize=8)
    ax1.set_ylim(0, max(115, sub_auto["step_latency_p95_ms"].max() * 1.15))
    ax1.set_xticks(xa)
    ax1.set_xticklabels(sub_auto["condition"])
    ax1.set_ylabel("Latency per Step (ms)")
    ax1.set_title("Per-Step Automated Defense Latency (C0 vs. C2–C5)")
    ax1.legend()

    rt_ttd = raw_sto[raw_sto["condition"].isin(["C3", "C4", "C5"])].dropna(subset=["time_to_detect_ms"])
    if not rt_ttd.empty:
        melted = pd.melt(
            rt_ttd[["condition", "time_to_detect_ms", "time_to_contain_ms"]],
            id_vars="condition",
            var_name="metric",
            value_name="ms",
        )
        melted["metric"] = melted["metric"].replace(
            {"time_to_detect_ms": "Time-to-Detect (ms)", "time_to_contain_ms": "Time-to-Contain (ms)"}
        )
        sns.boxplot(data=melted, x="condition", y="ms", hue="metric", ax=ax2)
        ax2.set_yscale("log")
        ax2.set_ylabel("Milliseconds (log scale)")
        ax2.set_title("Pillar 3 Runtime Anomaly Detect & Kill-Switch Contain")
        ax2.legend(title="")
    fig.tight_layout()
    p4 = fig_dir / "fig4_latency_and_containment.png"
    fig.savefig(p4, dpi=300)
    plt.close(fig)
    generated.append(p4)

    # --- Figure 5: Unseen Holdout Generalization & Hard Dual-Use Benign Utility ---
    fig, ax = plt.subplots(figsize=(8.8, 4.6))
    xh = np.arange(len(holdout))
    wh = 0.25
    ax.bar(xh - wh, holdout["asr_mean_pct"], yerr=holdout["asr_ci95_pct"], width=wh, capsize=3, label="Unseen Attack Success Rate (%)", color="#d62728")
    ax.bar(xh, holdout["block_detect_mean_pct"], yerr=holdout["block_detect_ci95_pct"], width=wh, capsize=3, label="Explicit Block/Detect Rate (%)", color="#1f77b4")
    ax.bar(xh + wh, holdout["benign_success_mean_pct"], yerr=holdout["benign_success_ci95_pct"], width=wh, capsize=3, label="Hard Benign Utility (%)", color="#2ca02c")
    h_labels = ["C0\nUndefended", "C4\nPre-Feedback", "C5-Regex\nRegex Only", "C5-Full\nRegex + MiniLM"]
    ax.set_xticks(xh)
    ax.set_xticklabels(h_labels)
    ax.set_ylim(0, 114)
    ax.set_ylabel("Percentage (%)")
    ax.set_title("Zero-Leakage Unseen Holdout Generalization & Hard Benign Utility (5 Seeds, 95% CI)", pad=28)
    ax.legend(loc="lower center", bbox_to_anchor=(0.5, 1.01), ncol=3, frameon=True)
    for i, r in holdout.iterrows():
        ax.text(i - wh, r["asr_mean_pct"] + r["asr_ci95_pct"] + 1.5, f"{r['asr_mean_pct']:.1f}", ha="center", fontsize=8)
        ax.text(i + wh, r["benign_success_mean_pct"] + r["benign_success_ci95_pct"] + 1.5, f"{r['benign_success_mean_pct']:.1f}", ha="center", fontsize=8)
    fig.tight_layout()
    p5 = fig_dir / "fig5_holdout_and_hard_benign.png"
    fig.savefig(p5, dpi=300, bbox_inches="tight")
    plt.close(fig)
    generated.append(p5)

    # --- Figure 6: Pillar 1 Control-Budget Prioritization Ablation ---
    fig, ax = plt.subplots(figsize=(8.4, 4.5))
    b_palette = {
        "Pillar 1 Risk-Ranked": "#2ca02c",
        "Random Control Subset": "#1f77b4",
        "Reverse-Risk": "#d62728",
    }
    for strat, grp in budget_df.groupby("strategy"):
        grp = grp.sort_values("budget_k")
        ax.errorbar(
            grp["budget_k"],
            grp["asr_mean_pct"],
            yerr=grp["asr_ci95_pct"],
            marker="o",
            linewidth=2,
            capsize=4,
            label=strat,
            color=b_palette.get(strat),
        )
    ax.set_xticks(sorted(budget_df["budget_k"].unique()))
    ax.set_xlabel("Enabled Security Control Budget (K of 11 Controls)")
    ax.set_ylabel("Attack Success Rate (%)")
    ax.set_title("Pillar 1 Impact×Likelihood Control Prioritization Under Resource Budget K")
    ax.legend(loc="upper right", frameon=True)
    fig.tight_layout()
    p6 = fig_dir / "fig6_pillar1_budget_ablation.png"
    fig.savefig(p6, dpi=300)
    plt.close(fig)
    generated.append(p6)

    for p in generated:
        print(f"Generated figure: {p}")
    return generated


def main() -> int:
    make_all_figures()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
