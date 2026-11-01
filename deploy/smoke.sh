#!/bin/sh
set -eu
{ set +x; } 2>/dev/null
LC_ALL=C
export LC_ALL

die() {
  code=$1
  shift
  printf 'smoke: %s\n' "$*" >&2
  exit "$code"
}

[ -n "${FLEET_SERVER_URL:-}" ] || die 2 "FLEET_SERVER_URL is not set"
[ -n "${FLEET_CLIENT_TOKEN:-}" ] || die 2 "FLEET_CLIENT_TOKEN is not set"
[ -n "${SMOKE_REPO:-}" ] || die 2 "SMOKE_REPO is not set"

base=${SMOKE_BASE-main}
agent=${SMOKE_AGENT-claude}
deadline=${SMOKE_DEADLINE_SECS-300}
fleet=${FLEET_BIN:-fleet}

printf '%s\n' "$agent" | grep -Eq '^[a-z0-9_-]{1,32}$' || die 2 "SMOKE_AGENT must match [a-z0-9_-]{1,32}"
printf '%s\n' "$deadline" | grep -Eq '^[0-9]{1,4}$' || die 2 "SMOKE_DEADLINE_SECS must be an integer from 10 to 3600"
[ "$deadline" -ge 10 ] && [ "$deadline" -le 3600 ] || die 2 "SMOKE_DEADLINE_SECS must be an integer from 10 to 3600"
[ -n "$base" ] || die 2 "SMOKE_BASE is empty"

key="smoke-$(date +%s)-$$-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
prompt='Read the repository README and reply with one sentence describing it. Do not modify any file.'

out=$("$fleet" submit --no-pr --agent "$agent" --repo "$SMOKE_REPO" --base "$base" --idempotency-key "$key" "$prompt") || die 1 "submit failed"
id=$(printf '%s\n' "$out" | head -n 1)
printf '%s\n' "$id" | grep -Eq '^[0-9A-Z]{26}$' || die 7 "submit returned an unusable job id"
printf 'smoke: submitted %s\n' "$id"

field() {
  printf '%s\n' "$1" | sed -n "s/^$2: //p" | head -n 1 | tr -cd '[:print:]' | cut -c 1-200
}

fail_logs() {
  "$fleet" logs "$id" 2>&1 | grep -v '^chmod:' | tr -cd '\n[:print:]' | head -c 4000 >&2 || true
}

max=$((deadline / 5))
n=0
while :; do
  n=$((n + 1))
  status=$("$fleet" status "$id" 2>/dev/null) || status=""
  state=$(field "$status" state)
  phase=$(field "$status" phase)
  printf 'smoke: state=%s phase=%s\n' "$state" "$phase"
  case $state in
    SUCCEEDED) exit 0 ;;
    FAILED)
      printf 'smoke: error=%s\n' "$(field "$status" error)" >&2
      fail_logs
      exit 3
      ;;
    CANCELLED)
      fail_logs
      exit 4
      ;;
    QUEUED | RUNNING) ;;
    *)
      fail_logs
      die 6 "unknown terminal state '$state'"
      ;;
  esac
  if [ "$n" -ge "$max" ]; then
    "$fleet" cancel "$id" >/dev/null 2>&1 || true
    fail_logs
    die 5 "deadline of ${deadline}s passed"
  fi
  sleep 5
done
