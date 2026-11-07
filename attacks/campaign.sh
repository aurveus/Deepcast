#!/usr/bin/env bash
# Unattended attack campaign — LAB ONLY, runs on Kali against the isolated VMnet1 range.
# Plays a randomised schedule of the documented scenarios (attacks/README.md) with random gaps, and writes its
# own attack ground truth: one JSON line per scenario with the real start and end time (UTC).
# Only the fixed scenario names below exist; nothing else can be passed in (no free-form commands).
#
# Usage (on Kali): campaign.sh [--runs N] [--idle N] [--seed S] [--gap-min SEC] [--gap-max SEC] [--only a,b,c]
#   --runs N    runs of each attack scenario (default 5)
#   --idle N    benign-only windows (no attack, just a pause) (default 3)
#   --only      restrict to these scenarios: portscan,slowscan,sshbrute,webprobe,lure,dirbrute,stealthscan,traverse,overlap
#   --idle-sec  length of one benign-only window in seconds (default 180)
#   --plan      exact counts instead of --runs/--idle, e.g. lure:2,webprobe:1,idle:1 (used by resume mode)
set -uo pipefail

TARGET="${LAB_TARGET:-10.10.10.1}"
LAB_PREFIX="${LAB_PREFIX:-10.10.10.}"
WEB_PORT="${LAB_WEB_PORT:-8080}"; SSH_PORT="${LAB_SSH_PORT:-2222}"
OUT="${LAB_CAMPAIGN_LOG:-$HOME/campaign.jsonl}"
PLAN=""; RUNS=5; IDLE=3; SEED=$$; GAP_MIN=300; GAP_MAX=420; ONLY="portscan,slowscan,sshbrute,webprobe,lure,dirbrute,stealthscan,traverse,overlap"; IDLE_SEC=180
while [ $# -gt 0 ]; do
  case "$1" in
    --runs) RUNS=$2; shift 2 ;; --idle) IDLE=$2; shift 2 ;; --seed) SEED=$2; shift 2 ;;
    --gap-min) GAP_MIN=$2; shift 2 ;; --gap-max) GAP_MAX=$2; shift 2 ;; --only) ONLY=$2; shift 2 ;; --plan) PLAN=$2; shift 2 ;; --idle-sec) IDLE_SEC=$2; shift 2 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
case "$TARGET" in "$LAB_PREFIX"*) ;; *) echo "target $TARGET outside lab range $LAB_PREFIX*" >&2; exit 1 ;; esac
for n in "$RUNS" "$IDLE" "$SEED" "$GAP_MIN" "$GAP_MAX" "$IDLE_SEC"; do [[ "$n" =~ ^[0-9]+$ ]] || { echo "numeric options only" >&2; exit 2; }; done
[ "$GAP_MAX" -ge "$GAP_MIN" ] || { echo "gap-max < gap-min" >&2; exit 2; }

HERE="$(cd "$(dirname "$0")" && pwd)"
WL=/tmp/campaign_wl; mkdir -p "$WL"
printf 'admin\nroot\nuser\ntest\nguest\noracle\nubuntu\npi\nadministrator\nservice\n' > "$WL/users.txt"
printf 'admin\npassword\n123456\nroot\ntoor\nletmein\nqwerty\nwelcome1\nchangeme\nsummer2024\n' > "$WL/pass.txt"
SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo -n"
if $SUDO true 2>/dev/null; then SYN="-sS"; else SUDO=""; SYN="-sT"; fi    # SYN scan needs root; fall back to connect scan

now() { date -u +%FT%TZ; }
RANDOM=$SEED

scenario_portscan() { $SUDO nmap -n $SYN -p- --min-rate 1000 "$TARGET" >/dev/null 2>&1; $SUDO nmap -n -sV -p 21,23,2222,4445,8080 "$TARGET" >/dev/null 2>&1; }
scenario_slowscan() { nmap -n -sT -T1 --scan-delay 5s -p 21,22,23,80,443,445,2222,3306,4445,8080 "$TARGET" >/dev/null 2>&1; }
scenario_sshbrute() { hydra -L "$WL/users.txt" -P "$WL/pass.txt" -s "$SSH_PORT" -t 4 "ssh://$TARGET" >/dev/null 2>&1; }
scenario_webprobe() {
  timeout 300 nikto -h "http://$TARGET:$WEB_PORT" >/dev/null 2>&1
  for p in admin/ backup/ login robots.txt; do curl -s -o /dev/null "http://$TARGET:$WEB_PORT/$p"; done
}
scenario_lure() { LAB_SIM_LOG=/tmp/campaign_lure.log LAB_PREFIX="$LAB_PREFIX" "$HERE/lure_chain_sim.sh" --fast >/dev/null 2>&1; }
scenario_idle() { sleep "$IDLE_SEC"; }
# Overlap: three different attacks at the same time from one host (a port scan, an SSH brute force and a directory brute force).
# Tests whether the platform reports every behavior when the traffic is not tidy and one-at-a-time.
scenario_overlap() { scenario_portscan & scenario_sshbrute & scenario_dirbrute & wait; }
# Deep trap traversal: lure -> credential -> interactive-style SSH walk through the lived-in server -> internal hosts -> credential reuse.
scenario_traverse() { LAB_SIM_LOG=/tmp/campaign_traverse.log LAB_PREFIX="$LAB_PREFIX" "$HERE/lure_chain_sim.sh" --fast --deep >/dev/null 2>&1; }
# Directory brute force: gobuster against the fake web admin panel. Standard wordlist, standard tool, own lab only.
scenario_dirbrute() {
  gobuster dir -u "http://$TARGET:$WEB_PORT" -w /usr/share/wordlists/dirb/common.txt -q -t 10 --timeout 5s -b 404 >/dev/null 2>&1
}
# Stealth scan: nmap's own evasion flags (fragmented probes, decoy source addresses) against the lab only.
# The decoys are FIXED unused addresses inside the lab range (never random Internet addresses: RND would put spoofed public
# IPs on the wire). Needs raw sockets: root, or `sudo setcap cap_net_raw,cap_net_admin+eip $(which nmap)` once on Kali.
STEALTH_DECOYS="${LAB_PREFIX}201,${LAB_PREFIX}202,${LAB_PREFIX}203,ME"
scenario_stealthscan() {
  $SUDO nmap -n -sS -f -D "$STEALTH_DECOYS" -p 21,22,23,80,443,445,2222,3306,4445,"$WEB_PORT" "$TARGET" >/dev/null 2>&1
}

# schedule: RUNS of each chosen attack + IDLE benign windows, shuffled with the seed (Fisher-Yates)
sched=()
if [ -n "$PLAN" ]; then
  IFS=, read -ra items <<< "$PLAN"
  for it in "${items[@]}"; do
    s=${it%%:*}; c=${it##*:}
    case "$s" in portscan|slowscan|sshbrute|webprobe|lure|dirbrute|stealthscan|traverse|overlap|idle) ;; *) echo "unknown scenario $s" >&2; exit 2 ;; esac
    [[ "$c" =~ ^[0-9]+$ ]] || { echo "bad count in plan: $it" >&2; exit 2; }
    for ((i = 0; i < c; i++)); do sched+=("$s"); done
  done
else
  IFS=, read -ra chosen <<< "$ONLY"
  for s in "${chosen[@]}"; do
    case "$s" in portscan|slowscan|sshbrute|webprobe|lure|dirbrute|stealthscan|traverse|overlap) ;; *) echo "unknown scenario $s" >&2; exit 2 ;; esac
    for ((i = 0; i < RUNS; i++)); do sched+=("$s"); done
  done
  for ((i = 0; i < IDLE; i++)); do sched+=(idle); done
fi
[ "${#sched[@]}" -gt 0 ] || { echo "nothing to run" >&2; exit 0; }
case " ${sched[*]} " in *" stealthscan "*)
  $SUDO nmap -n -sS -p 1 127.0.0.1 >/dev/null 2>&1 || { echo "stealthscan needs raw sockets (root or setcap on nmap); nothing was run" >&2; exit 3; } ;;
esac
for ((i = ${#sched[@]} - 1; i > 0; i--)); do j=$((RANDOM % (i + 1))); t=${sched[i]}; sched[i]=${sched[j]}; sched[j]=$t; done

: > "$OUT"
printf '{"event":"campaign_started","ts":"%s","seed":%s,"target":"%s","total":%s}\n' "$(now)" "$SEED" "$TARGET" "${#sched[@]}" >> "$OUT"
n=0
for s in "${sched[@]}"; do
  n=$((n + 1)); start=$(now)
  "scenario_$s"; rc=$?
  printf '{"event":"scenario","n":%s,"scenario":"%s","attack":%s,"target":"%s","start":"%s","end":"%s","rc":%s}\n' \
    "$n" "$s" "$([ "$s" = idle ] && echo false || echo true)" "$TARGET" "$start" "$(now)" "$rc" >> "$OUT"
  [ "$n" -lt "${#sched[@]}" ] && sleep $((RANDOM % (GAP_MAX - GAP_MIN + 1) + GAP_MIN))
done
printf '{"event":"campaign_finished","ts":"%s"}\n' "$(now)" >> "$OUT"
