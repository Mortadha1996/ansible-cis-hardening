#!/usr/bin/env bash
# CIS compliance check for the ansible-cis-hardening role.
# Reads actual system state — does not trust Ansible's report.
# Run before and after the playbook to measure the delta.

PASS=0
FAIL=0
RESULTS=()

check() {
  local name="$1"
  local condition="$2"
  if eval "$condition" &>/dev/null; then
    RESULTS+=("PASS|$name")
    ((PASS++))
  else
    RESULTS+=("FAIL|$name")
    ((FAIL++))
  fi
}

echo "CIS compliance check — $(hostname) — $(date)"
echo "══════════════════════════════════════════════════════"
echo ""

# ── SSH ─────────────────────────────────────────────────
check "SSH: root login disabled"          "grep -qE '^PermitRootLogin\s+no' /etc/ssh/sshd_config"
check "SSH: password auth disabled"       "grep -qE '^PasswordAuthentication\s+no' /etc/ssh/sshd_config"
check "SSH: empty passwords refused"      "grep -qE '^PermitEmptyPasswords\s+no' /etc/ssh/sshd_config"
check "SSH: MaxAuthTries <= 4"            "grep -qE '^MaxAuthTries\s+[1-4]$' /etc/ssh/sshd_config"
check "SSH: X11 forwarding disabled"      "grep -qE '^X11Forwarding\s+no' /etc/ssh/sshd_config"

# ── Kernel ──────────────────────────────────────────────
check "Kernel: IP forwarding off"         "[ \$(sysctl -n net.ipv4.ip_forward) = '0' ]"
check "Kernel: source routing off"        "[ \$(sysctl -n net.ipv4.conf.all.accept_source_route) = '0' ]"
check "Kernel: ICMP redirects refused"    "[ \$(sysctl -n net.ipv4.conf.all.accept_redirects) = '0' ]"
check "Kernel: SYN cookies enabled"       "[ \$(sysctl -n net.ipv4.tcp_syncookies) = '1' ]"
check "Kernel: ASLR enabled"              "[ \$(sysctl -n kernel.randomize_va_space) = '2' ]"
check "Kernel: suid dumps disabled"       "[ \$(sysctl -n fs.suid_dumpable) = '0' ]"
check "Kernel: dmesg restricted"          "[ \$(sysctl -n kernel.dmesg_restrict) = '1' ]"
check "Kernel: kptr restricted"           "[ \$(sysctl -n kernel.kptr_restrict) = '2' ]"

# ── Filesystem ──────────────────────────────────────────
check "FS: /tmp mounted noexec"           "mount | grep -E ' on /tmp ' | grep -q noexec"
check "FS: /var/tmp mounted noexec"       "mount | grep -E ' on /var/tmp ' | grep -q noexec"
check "FS: /dev/shm mounted noexec"       "mount | grep -E ' on /dev/shm ' | grep -q noexec"

# ── Password policy ────────────────────────────────────
check "Password: max age <= 90"           "grep -qE '^PASS_MAX_DAYS\s+([1-9]|[1-8][0-9]|90)$' /etc/login.defs"
check "Password: min length 14"           "grep -qE '^minlen\s*=\s*1[4-9]' /etc/security/pwquality.conf"
check "Password: SHA512 hashing"          "grep -qE '^ENCRYPT_METHOD\s+SHA512' /etc/login.defs"

# ── Audit ──────────────────────────────────────────────
check "Audit: auditd installed"           "command -v auditctl"
check "Audit: auditd running"             "systemctl is-active --quiet auditd"
check "Audit: CIS rules loaded"           "[ \$(auditctl -l 2>/dev/null | wc -l) -gt 0 ]"

# ── Firewall (nftables) ────────────────────────────────
check "Firewall: nftables active"         "systemctl is-active --quiet nftables"
check "Firewall: input policy drop"       "nft list chain inet filter input 2>/dev/null | grep -q 'policy drop'"
check "Firewall: SSH 22 allowed"          "nft list chain inet filter input 2>/dev/null | grep -q 'tcp dport 22 accept'"

# ── Banner ─────────────────────────────────────────────
check "Banner: /etc/issue set"            "[ -s /etc/issue ]"
check "Banner: /etc/issue.net set"        "[ -s /etc/issue.net ]"

# ── Output ─────────────────────────────────────────────
for r in "${RESULTS[@]}"; do
  STATUS="${r%%|*}"
  NAME="${r#*|}"
  if [ "$STATUS" = "PASS" ]; then
    printf "  \033[32m✓\033[0m  %s\n" "$NAME"
  else
    printf "  \033[31m✗\033[0m  %s\n" "$NAME"
  fi
done

TOTAL=$((PASS + FAIL))
PERCENT=$((PASS * 100 / TOTAL))

echo ""
echo "══════════════════════════════════════════════════════"
printf "  Passed: %d / %d   —   \033[1m%d%% compliant\033[0m\n" "$PASS" "$TOTAL" "$PERCENT"
echo "══════════════════════════════════════════════════════"
