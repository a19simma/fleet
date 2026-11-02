#!/bin/bash
set -euo pipefail
LC_ALL=C
export LC_ALL

UNIT=${FLEET_PROBE_UNIT:-fleet-agent@.service}
PORT=${FLEET_PROBE_PORT:-47931}
DIR=/var/lib/fleet/jobs/.probe-loopback.$$
SOCK=$DIR/otlp.sock
WAIT=20
KEYS="User Group UMask NoNewPrivileges ProtectSystem ProtectHome ProtectProc ProcSubset PrivateNetwork PrivateTmp RestrictAddressFamilies RestrictSUIDSGID LockPersonality CapabilityBoundingSet IPAddressAllow IPAddressDeny ReadWritePaths"
PASSED=0
FAILED=0
LISTENER_PID=

die() {
  printf 'probe: %s\n' "$*" >&2
  exit 2
}

cleanup() {
  if [ -n "$LISTENER_PID" ]; then
    kill "$LISTENER_PID" 2>/dev/null || true
    wait "$LISTENER_PID" 2>/dev/null || true
  fi
  if [ -d "$DIR" ]; then
    rm -f "$SOCK"
    rmdir "$DIR" 2>/dev/null || true
  fi
}

report() {
  printf '%s %s\n' "$1" "$2"
  if [ "$1" = PASS ]; then
    PASSED=$((PASSED + 1))
  else
    FAILED=$((FAILED + 1))
  fi
}

[ "$(uname -s)" = Linux ] || die "needs a Linux host with the unit installed"
[ "$(id -u)" -eq 0 ] || die "run as root: systemd-run needs it"
command -v systemd-run >/dev/null || die "systemd-run missing"
command -v python3 >/dev/null || die "python3 missing"
systemctl cat "$UNIT" >/dev/null 2>&1 || die "unit $UNIT is not installed"
[ -d /var/lib/fleet/jobs ] || die "/var/lib/fleet/jobs missing"

UNIT_PROPS=()
while IFS= read -r line; do
  key=${line%%=*}
  case " $KEYS " in
    *" $key "*) UNIT_PROPS+=("$line") ;;
  esac
done < <(systemctl cat "$UNIT" | sed -n '/^\[Service\]/,/^\[/p' | grep -E '^[A-Za-z]+=')
[ "${#UNIT_PROPS[@]}" -gt 0 ] || die "no sandbox directives read from $UNIT"

has_directive() {
  local p
  for p in "${UNIT_PROPS[@]}"; do
    [ "${p%%=*}" = "$1" ] && return 0
  done
  return 1
}

CLIENT_TCP='import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.settimeout(3)
s.connect(("127.0.0.1",int(sys.argv[1])))
s.sendall(b"ping")
sys.exit(0 if s.recv(4)==b"pong" else 1)'
CLIENT_UNIX='import socket,sys
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
s.settimeout(3)
s.connect(sys.argv[1])
s.sendall(b"ping")
sys.exit(0 if s.recv(4)==b"pong" else 1)'
CLIENT_NSLOOP='import socket,sys
l=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
l.bind(("127.0.0.1",0))
l.listen(1)
c=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
c.settimeout(3)
c.connect(l.getsockname())
sys.exit(0)'
SERVER='import os,socket,sys,threading
def serve(s):
    while True:
        c,_=s.accept()
        c.recv(4)
        c.sendall(b"pong")
        c.close()
t=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
t.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
t.bind(("127.0.0.1",int(sys.argv[1])))
t.listen(8)
u=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
u.bind(sys.argv[2])
os.chmod(sys.argv[2],0o666)
u.listen(8)
threading.Thread(target=serve,args=(u,),daemon=True).start()
sys.stdout.write("ready\n")
sys.stdout.flush()
serve(t)'

run_unit() {
  local overrides=() skip=" " arg p
  while [ "$#" -gt 0 ]; do
    if [ "$1" = -- ]; then
      shift
      break
    fi
    overrides+=("$1")
    skip="$skip${1%%=*} "
    shift
  done
  local props=()
  for p in "${UNIT_PROPS[@]}"; do
    case "$skip" in
      *" ${p%%=*} "*) ;;
      *) props+=("-p" "$p") ;;
    esac
  done
  for arg in "${overrides[@]}"; do
    props+=("-p" "$arg")
  done
  timeout "$WAIT" systemd-run --quiet --wait --collect --pipe \
    -p ReadWritePaths="$DIR" "${props[@]}" "$@"
}

expect() {
  local label=$1 want=$2
  shift 2
  local got=FAIL
  if "$@" >/dev/null 2>&1; then
    got=OK
  fi
  if [ "$got" = "$want" ]; then
    report PASS "$label (expected $want, got $got)"
  else
    report FAIL "$label (expected $want, got $got)"
  fi
}

transport() {
  local name=$1
  shift
  if "$@" >/dev/null 2>&1; then
    printf 'PASS transport %s reachable from the unit sandbox\n' "$name"
  else
    printf 'FAIL transport %s not reachable from the unit sandbox\n' "$name"
  fi
}

mkdir -m 0755 "$DIR"
trap cleanup EXIT INT TERM

python3 -c "$SERVER" "$PORT" "$SOCK" >"$DIR/server.out" 2>&1 &
LISTENER_PID=$!
tries=0
until grep -q ready "$DIR/server.out" 2>/dev/null; do
  tries=$((tries + 1))
  [ "$tries" -le 50 ] || die "host listener did not start: $(cat "$DIR/server.out")"
  kill -0 "$LISTENER_PID" 2>/dev/null || die "host listener exited: $(cat "$DIR/server.out")"
  sleep 0.1
done
rm -f "$DIR/server.out"

printf '== directives read from %s ==\n' "$UNIT"
printf '%s\n' "${UNIT_PROPS[@]}"
if has_directive IPAddressAllow || has_directive IPAddressDeny; then
  printf 'note: unit sets IPAddressAllow/Deny; the probes below cover it as part of the unit baseline\n'
else
  printf 'note: unit sets no IPAddressAllow/IPAddressDeny; no probe applies\n'
fi

printf '== controls: host side, no sandbox ==\n'
expect "control host TCP client reaches host listener" OK python3 -c "$CLIENT_TCP" "$PORT"
expect "control host unix client reaches host listener" OK python3 -c "$CLIENT_UNIX" "$SOCK"
[ "$FAILED" -eq 0 ] || die "precondition absent: host listener unreachable even without a sandbox"

printf '== control: sandbox shell runs as the unit user at all ==\n'
expect "control unit sandbox runs a trivial command" OK run_unit -- /usr/bin/python3 -c "pass"
[ "$FAILED" -eq 0 ] || die "precondition absent: sandbox with unit directives cannot run python3"

printf '== directive: PrivateNetwork ==\n'
expect "control PrivateNetwork=no: loopback TCP reaches host listener" OK \
  run_unit PrivateNetwork=no -- /usr/bin/python3 -c "$CLIENT_TCP" "$PORT"
expect "control PrivateNetwork=yes: in-namespace loopback works (socket() allowed)" OK \
  run_unit -- /usr/bin/python3 -c "$CLIENT_NSLOOP"
transport "loopback-tcp" run_unit -- /usr/bin/python3 -c "$CLIENT_TCP" "$PORT"

printf '== directive: RestrictAddressFamilies ==\n'
expect "control AF_UNIX only, PrivateNetwork=no: loopback TCP is blocked" FAIL \
  run_unit PrivateNetwork=no "RestrictAddressFamilies=AF_UNIX" -- /usr/bin/python3 -c "$CLIENT_TCP" "$PORT"
expect "control unit families, PrivateNetwork=no: loopback TCP works" OK \
  run_unit PrivateNetwork=no -- /usr/bin/python3 -c "$CLIENT_TCP" "$PORT"
expect "control AF_UNIX only keeps unix sockets usable" OK \
  run_unit "RestrictAddressFamilies=AF_UNIX" -- /usr/bin/python3 -c "$CLIENT_UNIX" "$SOCK"

printf '== directive: unix socket path (ReadWritePaths, ProtectSystem, PrivateTmp) ==\n'
expect "control PrivateTmp socket outside the bound dir is invisible" FAIL \
  run_unit -- /usr/bin/python3 -c "$CLIENT_UNIX" /tmp/fleet-probe-absent.sock
transport "unix-socket" run_unit -- /usr/bin/python3 -c "$CLIENT_UNIX" "$SOCK"

printf '== summary ==\n'
printf 'passed=%s failed=%s\n' "$PASSED" "$FAILED"
printf 'Transport lines are results, not checks: they do not change the exit code. Exit 1 means a control or directive probe disagreed with its expectation.\n'
[ "$FAILED" -eq 0 ]
