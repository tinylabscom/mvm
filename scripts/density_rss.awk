BEGIN {
  print "component\tcount\trss_kib\trss_mib"
  n = split("mvm-hvf-supervisor firecracker mvm-network-endpoint mvm-mailbox mvm-host-agent mvm-signer-helper mvm-host-signer mvm-audit-signer mvm-broker mvmctl", names, " ")
}
{
  rss = $2
  if ($3 ~ /awk$/) next
  # The wave directory names its backend and appears in helper arguments.
  # Classify by the program file, not by a component name elsewhere on the line.
  program = $4
  sub(/.*\//, "", program)
  for (i = 1; i <= n; i++) {
    if (program == names[i] || index(program, names[i] "-") == 1) {
      count[names[i]]++
      rss_kib[names[i]] += rss
      break
    }
  }
}
END {
  for (name in count) {
    printf "%s\t%d\t%d\t%.1f\n", name, count[name], rss_kib[name], rss_kib[name] / 1024
  }
}
