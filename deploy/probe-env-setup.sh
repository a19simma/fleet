#!/bin/bash
# Live-host probe of the sandbox directives of deploy/fleet-env@.service (ADR-0067 decision 6).
#
# Run on a Box as root: bash deploy/probe-env-setup.sh
# Dry mode: bash deploy/probe-env-setup.sh --list
#   prints "<probe name> <directive,directive>" per probe and touches nothing.
#
# Every probe runs the unit's own [Service] properties (read with systemctl cat) in a
# transient unit, so the probe tests what is installed, not a copy. Each probe first runs a
# positive control that proves the probe can see the thing it expects to be hidden or denied.
# A probe whose control is absent is FAIL, never PASS. The result is one line per probe,
# "PASS|FAIL <name> <detail>", recorded in a file whose path is printed on the first line.
#
# Exit 0: every probe PASS. Exit 1: a FAIL or a missing control. Exit 2: a precondition.
#
# Network: the only targets are 1.1.1.1:443 (net-external-unreachable, and its host control)
# and the unix socket /run/fleet-env/<id>/job.sock (proxy-path). No file under /etc/swarm,
# no env file and no credential is opened: /etc/swarm is only stat-ed and access-checked.
# Host fixtures are created one at a time under the id probe<pid>, an existing name is
# refused, and the cleanup trap is armed only after the first fixture exists.
set -euo pipefail
LC_ALL=C
export LC_ALL

UNIT_NAME=fleet-env@.service
AGENT_UNIT_NAME=fleet-agent@.service
SKIP_KEYS=" ExecStart Type RemainAfterExit Restart Environment EnvironmentFile StandardOutput ExecStopPost "

PROBES=(
  "slice|Slice|probe_slice"
  "identity-umask|User,Group,UMask|probe_identity"
  "net-lo-only|PrivateNetwork|probe_net_lo"
  "net-external-unreachable|PrivateNetwork|probe_net_external"
  "proxy-path|PrivateNetwork,BindReadOnlyPaths|probe_proxy"
  "etc-swarm-inaccessible|InaccessiblePaths|probe_etc_swarm"
  "run-fleet-hidden|TemporaryFileSystem|probe_run_fleet"
  "run-fleet-env-siblings-hidden|TemporaryFileSystem,BindReadOnlyPaths|probe_run_env_siblings"
  "no-cap-net-raw|CapabilityBoundingSet|probe_cap_net_raw"
  "runtime-max-kills-sleeper|RuntimeMaxSec|probe_runtime_max"
  "protect-proc-invisible|ProtectProc|probe_protect_proc"
  "proc-subset-pid|ProcSubset|probe_proc_subset"
  "private-tmp|PrivateTmp|probe_private_tmp"
  "env-dir-unreadable-from-agent|BindReadOnlyPaths|probe_env_dir_agent"
  "env-out-writable-visible|BindPaths,BindReadOnlyPaths,ProtectSystem|probe_env_out"
  "no-new-privs|NoNewPrivileges|probe_nnp"
  "protect-system-strict|ProtectSystem|probe_protect_system"
  "protect-home|ProtectHome|probe_protect_home"
  "limits-memory-tasks|MemoryMax,TasksMax|probe_limits"
  "address-families|RestrictAddressFamilies|probe_families"
  "suid-sgid|RestrictSUIDSGID|probe_suid"
  "lock-personality|LockPersonality|probe_personality"
)

if [ "${1:-}" = --list ]; then
  for entry in "${PROBES[@]}"; do
    rest=${entry#*|}
    printf '%s %s\n' "${entry%%|*}" "${rest%%|*}"
  done
  exit 0
fi
[ "$#" -eq 0 ] || { printf 'usage: %s [--list]\n' "$0" >&2; exit 2; }

die() {
  printf 'probe-env-setup: %s\n' "$*" >&2
  exit 2
}

[ "$(uname -s)" = Linux ] || die "needs a Linux host with the units installed"
[ "$(id -u)" -eq 0 ] || die "run as root: systemd-run needs it"
for tool in systemd-run systemctl python3 timeout mktemp getent; do
  command -v "$tool" >/dev/null || die "$tool missing"
done
PY=$(command -v python3)
case "$PY" in
  /home/* | /root/* | /tmp/* | /var/tmp/*) die "python3 at $PY is hidden by the sandbox" ;;
esac
systemctl cat "$UNIT_NAME" >/dev/null 2>&1 || die "$UNIT_NAME is not installed"
systemctl cat "$AGENT_UNIT_NAME" >/dev/null 2>&1 || die "$AGENT_UNIT_NAME is not installed"
getent passwd fleet-job >/dev/null || die "user fleet-job missing"
getent group fleet-work >/dev/null || die "group fleet-work missing"
for need in /var/lib/fleet/jobs /var/lib/fleet/tools /run/fleet/hook; do
  [ -d "$need" ] || die "$need missing, the agent unit would fail to start"
done

OUT=$(mktemp /var/tmp/probe-env-setup.XXXXXX)
printf 'output: %s\n' "$OUT"

ID=probe$$
RUN_ENV=/run/fleet-env
RUN_AGENT=/run/fleet
ENVDIR=$RUN_ENV/$ID
OUTDIR=$ENVDIR/out
SOCK=$ENVDIR/job.sock
AGDIR=$RUN_AGENT/$ID
OTHER_AGENT=$RUN_AGENT/other-$ID
OTHER_ENV=$RUN_ENV/other-$ID
TMPMARK=/tmp/probe-env-$ID
ETCMARK=/etc/probe-env-$ID
CURRENT_UNIT=
SERVER_PID=
SLEEPER_PID=
MADE=()
COUNTER=0
PASSED=0
FAILED=0
MISSING=0

cleanup() {
  local rc=$? p i
  if [ -n "$CURRENT_UNIT" ]; then
    systemctl stop "$CURRENT_UNIT" >/dev/null 2>&1 || true
  fi
  for p in "$SERVER_PID" "$SLEEPER_PID"; do
    if [ -n "$p" ]; then
      kill "$p" 2>/dev/null || true
      wait "$p" 2>/dev/null || true
    fi
  done
  rm -f "$SOCK" "$OUTDIR/marker" "$OUTDIR/suid" "$AGDIR/envd/out/marker" "$TMPMARK" "$ETCMARK"
  for ((i = ${#MADE[@]} - 1; i >= 0; i--)); do
    rmdir "${MADE[$i]}" 2>/dev/null || printf 'probe-env-setup: left %s\n' "${MADE[$i]}" >&2
  done
  exit "$rc"
}

fixture_dir() {
  local path=$1 mode=$2 owner=$3
  [ ! -e "$path" ] || die "$path exists, refusing to reuse it"
  mkdir -m "$mode" "$path"
  MADE+=("$path")
  trap cleanup EXIT INT TERM
  chown "$owner" "$path"
}

report() {
  printf '%s %s %s\n' "$1" "$2" "$3" | tee -a "$OUT"
  if [ "$1" = PASS ]; then
    PASSED=$((PASSED + 1))
  else
    FAILED=$((FAILED + 1))
  fi
}

pass() { report PASS "$1" "$2"; }
fail() { report FAIL "$1" "$2"; }
nocontrol() {
  MISSING=$((MISSING + 1))
  report FAIL "$1" "control absent: $2"
}

read_props() {
  local unit=$1 line key
  while IFS= read -r line; do
    key=${line%%=*}
    case "$SKIP_KEYS" in
      *" $key "*) ;;
      *) printf '%s\n' "${line//%i/$ID}" ;;
    esac
  done < <(systemctl cat "$unit" | sed -n '/^\[Service\]/,/^\[/p' | grep -E '^[A-Za-z]+=')
}

mapfile -t ENV_PROPS < <(read_props "$UNIT_NAME")
mapfile -t AGENT_PROPS < <(read_props "$AGENT_UNIT_NAME")
[ "${#ENV_PROPS[@]}" -gt 0 ] || die "no directives read from $UNIT_NAME"
[ "${#AGENT_PROPS[@]}" -gt 0 ] || die "no directives read from $AGENT_UNIT_NAME"

unit_value() {
  local p
  for p in "${ENV_PROPS[@]}"; do
    [ "${p%%=*}" = "$1" ] && { printf '%s' "${p#*=}"; return 0; }
  done
  return 1
}

U_OUT=
U_RC=0
unit_run() {
  local role=$1 limit=$2
  shift 2
  local overrides=() base skip=" " args=() p k
  while [ "$#" -gt 0 ] && [ "$1" != -- ]; do
    overrides+=("$1")
    skip="$skip${1%%=*} "
    shift
  done
  shift
  if [ "$role" = agent ]; then base=("${AGENT_PROPS[@]}"); else base=("${ENV_PROPS[@]}"); fi
  for p in "${base[@]}"; do
    k=${p%%=*}
    case "$skip" in *" $k "*) ;; *) args+=(-p "$p") ;; esac
  done
  for p in ${overrides[@]+"${overrides[@]}"}; do
    [ "${p#*=}" = "" ] || args+=(-p "$p")
  done
  COUNTER=$((COUNTER + 1))
  local name=fleet-env-probe-$ID-$COUNTER
  [ "$(systemctl show -p LoadState --value "$name.service" 2>/dev/null)" = not-found ] \
    || die "unit $name exists, refusing to reuse it"
  CURRENT_UNIT=$name.service
  U_RC=0
  U_OUT=$(timeout "$limit" systemd-run --quiet --wait --collect --pipe --unit="$name" \
    "${args[@]}" "$@" </dev/null 2>&1) || U_RC=$?
  if [ "$U_RC" -eq 124 ]; then
    systemctl stop "$CURRENT_UNIT" >/dev/null 2>&1 || true
  fi
  CURRENT_UNIT=
}

OBS=
OBS_DETAIL=
obs() {
  local role=$1
  shift
  unit_run "$role" 60 "$@"
  OBS_DETAIL=$(printf '%s\n' "$U_OUT" | tail -n 1 | cut -c1-160)
  case "$U_RC" in
    10) OBS=yes ;;
    11) OBS=no ;;
    *) OBS=error; OBS_DETAIL="rc=$U_RC ${OBS_DETAIL:-no output}" ;;
  esac
}

host_obs() {
  local rc=0
  OBS_DETAIL=$("$PY" -c "$1" "${@:2}" 2>&1 | tail -n 1 | cut -c1-160) || true
  "$PY" -c "$1" "${@:2}" >/dev/null 2>&1 || rc=$?
  case "$rc" in
    10) OBS=yes ;;
    11) OBS=no ;;
    *) OBS=error; OBS_DETAIL="rc=$rc ${OBS_DETAIL:-no output}" ;;
  esac
}

ROLE="env"
CTRL_OV=()
TEST_OV=()
ARGS=()

pair() {
  local name=$1 want=$2 code=$3 msg=$4 other=yes cdetail
  [ "$want" = yes ] && other=no
  obs "$ROLE" ${CTRL_OV[@]+"${CTRL_OV[@]}"} -- "$PY" -c "$code" ${ARGS[@]+"${ARGS[@]}"}
  if [ "$OBS" != "$other" ]; then
    nocontrol "$name" "$msg: control run saw $OBS, wanted $other ($OBS_DETAIL)"
    return
  fi
  cdetail=$OBS_DETAIL
  obs "$ROLE" ${TEST_OV[@]+"${TEST_OV[@]}"} -- "$PY" -c "$code" ${ARGS[@]+"${ARGS[@]}"}
  if [ "$OBS" = "$want" ]; then
    pass "$name" "$msg: $OBS_DETAIL; control: $cdetail"
  else
    fail "$name" "$msg not observed, saw $OBS ($OBS_DETAIL); control: $cdetail"
  fi
}

ROOT_OV=(User=root Group=root)

PY_CGROUP='import sys
sys.stdout.write(open("/proc/self/cgroup").read().strip().splitlines()[-1] + "\n")
sys.exit(10 if "system-fleet\\x2denv.slice" in open("/proc/self/cgroup").read() else 11)'
PY_IDENT='import grp,os,pwd,stat,sys
uid_ok = os.getuid() == pwd.getpwnam("fleet-job").pw_uid
gid_ok = os.getgid() == grp.getgrnam("fleet-work").gr_gid
mode = None
try:
    path = os.path.join(sys.argv[1], "idfile")
    fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o666)
    os.close(fd)
    mode = stat.S_IMODE(os.stat(path).st_mode)
    os.unlink(path)
except OSError:
    pass
print("uid=%d gid=%d umask-mode=%s" % (os.getuid(), os.getgid(), oct(mode) if mode is not None else "none"))
sys.exit(10 if uid_ok and gid_ok and mode == 0o600 else 11)'
PY_ONLYLO='import array,fcntl,socket,struct,sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
buf = array.array("B", bytes(4096))
addr, _ = buf.buffer_info()
out = fcntl.ioctl(s.fileno(), 0x8912, struct.pack("iL", len(buf), addr))
used = struct.unpack("iL", out)[0]
raw = buf.tobytes()[:used]
step = 40 if struct.calcsize("P") == 8 else 32
names = sorted({raw[i:i + 16].split(b"\0")[0].decode() for i in range(0, used, step)})
print("interfaces=" + ",".join(names))
sys.exit(10 if names == ["lo"] else 11)'
PY_CONNECT='import socket,sys
s = socket.socket()
s.settimeout(3)
try:
    s.connect(("1.1.1.1", 443))
    print("connected")
    sys.exit(10)
except OSError as e:
    print("errno=%s" % e.errno)
    sys.exit(11)'
PY_LOOP='import socket,sys
l = socket.socket()
l.bind(("127.0.0.1", 0))
l.listen(1)
c = socket.socket()
c.settimeout(3)
try:
    c.connect(l.getsockname())
    print("lo connect ok")
    sys.exit(10)
except OSError as e:
    print("lo errno=%s" % e.errno)
    sys.exit(11)'
PY_UNIXPING='import socket,sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(3)
try:
    s.connect(sys.argv[1])
    s.sendall(b"ping")
    got = s.recv(4)
    print("reply=%r" % got)
    sys.exit(10 if got == b"pong" else 11)
except OSError as e:
    print("errno=%s" % e.errno)
    sys.exit(11)'
PY_SERVER='import os,socket,sys
u = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
u.bind(sys.argv[1])
os.chmod(sys.argv[1], 0o666)
u.listen(8)
while True:
    c, _ = u.accept()
    c.recv(4)
    c.sendall(b"pong")
    c.close()'
PY_ACCESS='import os,sys
ok = os.access(sys.argv[1], os.R_OK | os.X_OK)
print("access=%s" % ok)
sys.exit(10 if ok else 11)'
PY_ANYENTRY='import os,sys
try:
    names = os.listdir(sys.argv[1])
except OSError as e:
    print("errno=%s" % e.errno)
    sys.exit(11)
print("entries=%d" % len(names))
sys.exit(10 if names else 11)'
PY_EXISTS='import os,sys
found = os.path.exists(sys.argv[1])
print("exists=%s" % found)
sys.exit(10 if found else 11)'
PY_CAPRAW='import socket,sys
bnd = [l.split()[1] for l in open("/proc/self/status") if l.startswith("CapBnd")][0]
try:
    socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP).close()
    print("raw socket created CapBnd=" + bnd)
    sys.exit(10)
except OSError as e:
    print("errno=%s CapBnd=%s" % (e.errno, bnd))
    sys.exit(11)'
PY_PID='import os,sys
found = os.path.isdir("/proc/" + sys.argv[1])
print("pid-visible=%s" % found)
sys.exit(10 if found else 11)'
PY_NNP='import sys
v = [l.split()[1] for l in open("/proc/self/status") if l.startswith("NoNewPrivs")][0]
print("NoNewPrivs=" + v)
sys.exit(10 if v == "1" else 11)'
PY_CREATE='import os,sys
try:
    fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT, 0o600)
    os.close(fd)
    os.unlink(sys.argv[1])
    print("created")
    sys.exit(10)
except OSError as e:
    print("errno=%s" % e.errno)
    sys.exit(11)'
PY_WRITE='import os,sys
try:
    fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.write(fd, b"probe")
    os.close(fd)
    print("written")
    sys.exit(10)
except OSError as e:
    print("errno=%s" % e.errno)
    sys.exit(11)'
PY_READ1='import sys
try:
    with open(sys.argv[1], "rb") as f:
        n = len(f.read(1))
    print("read=%d" % n)
    sys.exit(10 if n == 1 else 11)
except OSError as e:
    print("errno=%s" % e.errno)
    sys.exit(11)'
PY_HIDDEN='import os,sys
try:
    os.listdir(sys.argv[1])
    print("listable")
    sys.exit(11)
except OSError as e:
    print("errno=%s mode=%o" % (e.errno, os.stat(sys.argv[1]).st_mode & 0o777))
    sys.exit(10)'
PY_LIMITS='import sys
def parse(text):
    mult = {"K": 1 << 10, "M": 1 << 20, "G": 1 << 30, "T": 1 << 40}
    return int(text[:-1]) * mult[text[-1]] if text[-1] in mult else int(text)
cg = open("/proc/self/cgroup").read().strip().splitlines()[-1].split("::", 1)[1]
base = "/sys/fs/cgroup" + cg
mem = open(base + "/memory.max").read().strip()
pids = open(base + "/pids.max").read().strip()
print("memory.max=%s pids.max=%s" % (mem, pids))
sys.exit(10 if mem == str(parse(sys.argv[1])) and pids == sys.argv[2] else 11)'
PY_NETLINK='import socket,sys
try:
    socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0).close()
    print("AF_NETLINK allowed")
    sys.exit(10)
except OSError as e:
    print("errno=%s" % e.errno)
    sys.exit(11)'
PY_SUID='import os,sys
path = os.path.join(sys.argv[1], "suid")
fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
os.close(fd)
try:
    os.chmod(path, 0o4755)
    print("setuid bit set")
    sys.exit(10)
except OSError as e:
    print("errno=%s" % e.errno)
    sys.exit(11)
finally:
    os.unlink(path)'
PY_PERSONA='import ctypes,sys
libc = ctypes.CDLL(None, use_errno=True)
r = libc.personality(8)
print("ret=%d errno=%d" % (r, ctypes.get_errno()))
sys.exit(10 if r != -1 else 11)'

probe_slice() {
  ROLE=env CTRL_OV=(Slice=system.slice) TEST_OV=() ARGS=()
  pair slice yes "$PY_CGROUP" "unit cgroup is in system-fleet\\x2denv.slice"
}

probe_identity() {
  ROLE=env CTRL_OV=(User=root Group=root UMask=0022) TEST_OV=() ARGS=("$OUTDIR")
  pair identity-umask yes "$PY_IDENT" "uid fleet-job, gid fleet-work, new file mode 0600"
}

probe_net_lo() {
  ROLE=env CTRL_OV=(PrivateNetwork=) TEST_OV=() ARGS=()
  pair net-lo-only yes "$PY_ONLYLO" "the unit holds the lo interface only"
}

probe_net_external() {
  ROLE=env CTRL_OV=(PrivateNetwork=) TEST_OV=() ARGS=()
  pair net-external-unreachable no "$PY_CONNECT" "1.1.1.1:443 is not reachable"
}

probe_proxy() {
  local name=proxy-path cdetail
  host_obs "$PY_UNIXPING" "$SOCK"
  if [ "$OBS" != yes ]; then
    nocontrol "$name" "host client cannot reach the probe job.sock ($OBS: $OBS_DETAIL)"
    return
  fi
  obs env BindReadOnlyPaths= BindPaths= -- "$PY" -c "$PY_UNIXPING" "$SOCK"
  if [ "$OBS" != no ]; then
    nocontrol "$name" "job.sock stays reachable with the binds removed ($OBS: $OBS_DETAIL)"
    return
  fi
  cdetail=$OBS_DETAIL
  obs env -- "$PY" -c "$PY_LOOP"
  if [ "$OBS" != yes ]; then
    fail "$name" "loopback inside the unit does not work ($OBS_DETAIL)"
    return
  fi
  obs env -- "$PY" -c "$PY_UNIXPING" "$SOCK"
  if [ "$OBS" = yes ]; then
    pass "$name" "lo works and job.sock answers from the unit (forwarder not exercised): $OBS_DETAIL; control: host ok, binds removed: $cdetail"
  else
    fail "$name" "job.sock does not answer from the unit ($OBS_DETAIL)"
  fi
}

probe_etc_swarm() {
  ROLE=env CTRL_OV=("${ROOT_OV[@]}" InaccessiblePaths=) TEST_OV=("${ROOT_OV[@]}") ARGS=(/etc/swarm)
  pair etc-swarm-inaccessible no "$PY_ACCESS" "/etc/swarm is not accessible even to uid 0 of the unit"
}

probe_run_fleet() {
  ROLE=env CTRL_OV=(TemporaryFileSystem=/run/fleet-env:ro) TEST_OV=() ARGS=(/run/fleet)
  pair run-fleet-hidden no "$PY_ANYENTRY" "no other Job dir under /run/fleet"
}

probe_run_env_siblings() {
  ROLE=env CTRL_OV=(TemporaryFileSystem=/run/fleet:ro) TEST_OV=() ARGS=("$OTHER_ENV")
  pair run-fleet-env-siblings-hidden no "$PY_EXISTS" "another /run/fleet-env/<id> is absent"
}

probe_cap_net_raw() {
  ROLE=env CTRL_OV=("${ROOT_OV[@]}" CapabilityBoundingSet=CAP_NET_RAW) TEST_OV=("${ROOT_OV[@]}") ARGS=()
  pair no-cap-net-raw no "$PY_CAPRAW" "no raw socket even as uid 0 of the unit"
}

probe_runtime_max() {
  local name=runtime-max-kills-sleeper started=$SECONDS elapsed
  unit_run env 40 RuntimeMaxSec=3 -- /bin/sh -c 'echo started; exec sleep 120'
  elapsed=$((SECONDS - started))
  case "$U_OUT" in
    *started*) ;;
    *)
      nocontrol "$name" "the sleeper never started (rc=$U_RC: $(printf '%s' "$U_OUT" | tail -n 1 | cut -c1-120))"
      return
      ;;
  esac
  if [ "$U_RC" -eq 124 ]; then
    fail "$name" "the sleeper outlived RuntimeMaxSec=3 by 40 s"
  elif [ "$U_RC" -ne 0 ] && [ "$elapsed" -ge 2 ] && [ "$elapsed" -le 30 ]; then
    pass "$name" "sleeper killed after ${elapsed}s with rc=$U_RC; the unit file sets RuntimeMaxSec=$(unit_value RuntimeMaxSec)"
  else
    fail "$name" "elapsed=${elapsed}s rc=$U_RC"
  fi
}

probe_protect_proc() {
  ROLE=env CTRL_OV=(ProtectProc= ProcSubset=) TEST_OV=() ARGS=("$SLEEPER_PID")
  pair protect-proc-invisible no "$PY_PID" "a root-owned process is invisible in /proc"
}

probe_proc_subset() {
  ROLE=env CTRL_OV=(ProcSubset=) TEST_OV=() ARGS=(/proc/sys)
  pair proc-subset-pid no "$PY_EXISTS" "/proc/sys is absent"
}

probe_private_tmp() {
  ROLE=env CTRL_OV=(PrivateTmp=) TEST_OV=() ARGS=("$TMPMARK")
  pair private-tmp no "$PY_EXISTS" "a host /tmp file is not visible"
}

probe_env_dir_agent() {
  local name=env-dir-unreadable-from-agent cdetail
  obs env -- "$PY" -c "$PY_ANYENTRY" "$ENVDIR"
  if [ "$OBS" != yes ]; then
    nocontrol "$name" "the setup unit cannot list its own $ENVDIR ($OBS: $OBS_DETAIL)"
    return
  fi
  cdetail=$OBS_DETAIL
  obs agent -- "$PY" -c "$PY_ANYENTRY" "$ENVDIR"
  case "$OBS" in
    no) pass "$name" "agent unit cannot list the setup dir: $OBS_DETAIL; control: setup unit lists it: $cdetail" ;;
    yes) fail "$name" "agent unit lists the setup dir: $OBS_DETAIL; control: $cdetail" ;;
    *) nocontrol "$name" "the agent unit did not run ($OBS_DETAIL)" ;;
  esac
}

probe_env_out() {
  local name=env-out-writable-visible detail
  obs env -- "$PY" -c "$PY_WRITE" "$ENVDIR/notout"
  if [ "$OBS" != no ]; then
    nocontrol "$name" "the setup dir outside out/ is writable ($OBS: $OBS_DETAIL)"
    return
  fi
  detail=$OBS_DETAIL
  obs env -- "$PY" -c "$PY_WRITE" "$OUTDIR/marker"
  if [ "$OBS" != yes ]; then
    fail "$name" "FLEET_ENV_OUT is not writable from the setup unit ($OBS_DETAIL)"
    return
  fi
  if [ ! -s "$OUTDIR/marker" ] || [ "$(stat -c %U "$OUTDIR/marker")" != fleet-job ]; then
    fail "$name" "the host does not see the setup unit write in out/"
    return
  fi
  cp "$OUTDIR/marker" "$AGDIR/envd/out/marker"
  chown fleet-job:fleet-work "$AGDIR/envd/out/marker"
  chmod 0440 "$AGDIR/envd/out/marker"
  obs agent -- "$PY" -c "$PY_READ1" "$AGDIR/envd/out/absent"
  if [ "$OBS" != no ]; then
    nocontrol "$name" "the agent unit reads a file that does not exist ($OBS: $OBS_DETAIL)"
    return
  fi
  obs agent -- "$PY" -c "$PY_READ1" "$AGDIR/envd/out/marker"
  if [ "$OBS" = yes ]; then
    pass "$name" "out/ writable and not outside it ($detail); the agent unit reads the file at envd/out; carry simulated by this probe, the launcher carry is not built"
  else
    fail "$name" "the agent unit cannot read envd/out/marker ($OBS_DETAIL)"
  fi
}

probe_nnp() {
  ROLE=env CTRL_OV=(NoNewPrivileges=) TEST_OV=() ARGS=()
  pair no-new-privs yes "$PY_NNP" "NoNewPrivs is 1"
}

probe_protect_system() {
  ROLE=env CTRL_OV=("${ROOT_OV[@]}" ProtectSystem=no) TEST_OV=("${ROOT_OV[@]}") ARGS=("$ETCMARK")
  pair protect-system-strict no "$PY_CREATE" "/etc is read-only even to uid 0 of the unit"
}

probe_protect_home() {
  ROLE=env CTRL_OV=(ProtectHome=) TEST_OV=() ARGS=(/home)
  pair protect-home yes "$PY_HIDDEN" "/home is inaccessible"
}

probe_limits() {
  local mem tasks
  mem=$(unit_value MemoryMax) || { nocontrol limits-memory-tasks "unit file has no MemoryMax"; return; }
  tasks=$(unit_value TasksMax) || { nocontrol limits-memory-tasks "unit file has no TasksMax"; return; }
  ROLE=env CTRL_OV=(MemoryMax=infinity TasksMax=infinity) TEST_OV=() ARGS=("$mem" "$tasks")
  pair limits-memory-tasks yes "$PY_LIMITS" "cgroup memory.max=$mem and pids.max=$tasks"
}

probe_families() {
  ROLE=env CTRL_OV=(RestrictAddressFamilies=) TEST_OV=() ARGS=()
  pair address-families no "$PY_NETLINK" "AF_NETLINK is refused"
}

probe_suid() {
  ROLE=env CTRL_OV=(RestrictSUIDSGID=) TEST_OV=() ARGS=("$OUTDIR")
  pair suid-sgid no "$PY_SUID" "chmod u+s is refused"
}

probe_personality() {
  ROLE=env CTRL_OV=(LockPersonality=) TEST_OV=() ARGS=()
  pair lock-personality no "$PY_PERSONA" "personality(PER_LINUX32) is refused"
}

setup_fixtures() {
  [ -d "$RUN_ENV" ] || { mkdir -m 0755 "$RUN_ENV"; MADE+=("$RUN_ENV"); trap cleanup EXIT INT TERM; }
  fixture_dir "$ENVDIR" 0750 fleet-job:fleet-work
  fixture_dir "$OUTDIR" 0770 fleet-job:fleet-work
  fixture_dir "$OTHER_ENV" 0750 fleet-job:fleet-work
  fixture_dir "$AGDIR" 0750 fleet-job:fleet-work
  fixture_dir "$AGDIR/envd" 0750 fleet-job:fleet-work
  fixture_dir "$AGDIR/envd/out" 0770 fleet-job:fleet-work
  fixture_dir "$OTHER_AGENT" 0750 fleet-job:fleet-work
  [ ! -e "$TMPMARK" ] || die "$TMPMARK exists, refusing to reuse it"
  [ ! -e "$ETCMARK" ] || die "$ETCMARK exists, refusing to reuse it"
  : >"$TMPMARK"
  chmod 0644 "$TMPMARK"
  sleep 300 &
  SLEEPER_PID=$!
  "$PY" -c "$PY_SERVER" "$SOCK" >/dev/null 2>&1 &
  SERVER_PID=$!
  local i
  for i in 1 2 3 4 5 6 7 8 9 10; do
    [ -S "$SOCK" ] && break
    sleep 0.5
  done
  [ -S "$SOCK" ] || die "the probe job.sock server did not start"
  sleep 0.5
}

setup_fixtures
for entry in "${PROBES[@]}"; do
  rest=${entry#*|}
  "${rest#*|}"
done

printf 'summary: %d pass, %d fail, %d control absent\n' "$PASSED" "$FAILED" "$MISSING" | tee -a "$OUT"
printf 'output: %s\n' "$OUT"
[ "$FAILED" -eq 0 ] && [ "$MISSING" -eq 0 ]
