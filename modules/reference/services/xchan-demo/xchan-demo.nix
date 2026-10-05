# SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
# SPDX-License-Identifier: Apache-2.0
#
# BRING-UP ONLY. Host-side orchestrator for the encrypted guest-to-guest LLM
# demo. The model runs in the server guest (admin-vm); two mutually
# distrusting client guests ask it questions over xchan, end-to-end
# encrypted between guests. The host only sequences the demo, it starts and
# stops guests and runs the client binary inside them over vsock ssh. It never
# holds a demo key and never sees plaintext.
#
# Sequence (each step logged as `DEMO step=<n> ...`; the guests' own `DEMO `
# lines, which name their client, are relayed unchanged; the run ends with
# `DEMO RESULT PASS` or `DEMO RESULT FAIL step=<n>`). PASS/FAIL is decided by
# the client's exit status, never by parsing its text:
#   0. wait (bounded) for all three guests, the clients' /dev/xchan0 and the
#      server's xchan-demo-server unit
#   1. teardownClient: N encrypted requests
#   2. teardownClient: --close-reopen (a closed channel errors, a fresh works;
#      the client runs exactly 2 requests in this mode)
#   3. systemctl stop microvm@<teardownClient>; wait until it is down, and check
#      the server and the other client stayed up
#   4. secondClient: N encrypted requests, with the first client gone
#   5. systemctl start microvm@<teardownClient>; wait for vsock + /dev/xchan0,
#      and check the server guest was not restarted
#   6. both clients in parallel, N requests each; both must succeed
#   7. each client again, N requests, over guest-to-guest shared memory
#      (g2gchan: EL2 maps the pages into both guests; no host in the path),
#      then teardownClient's --close-reopen over it; the g2g server must not
#      have restarted (it is Restart=always, so a crash would otherwise hide)
#   8. g2gc-echo streams between the server and teardownClient, and the host
#      stops teardownClient mid-stream: EL2 dismantles its shares as its
#      teardown starts, the server's g2gc-echo must end cleanly (the client
#      went away), and teardownClient comes back
#
# What reaches the host journal: everything the client prints (relayed over
# ssh), so the host orchestrator never passes --show-text, by default the
# client prints only reply lengths, nothing derived from the decrypted reply
# (not even a digest: the host knows prompt and model, so it could check a
# guessed reply against one). The PROMPT is not secret from the host in this
# demo: it travels on the host-side ssh command line, so the defaults are
# deliberately neutral.
#
# For the console: `xchan-guest <admin|net|client> '<cmd>'` runs one bounded
# command in a guest; `xchan-demo-report` prints every piece of demo evidence,
# host and guests, as plain text.
#
# Runs once per boot from a timer (not from multi-user.target: a oneshot
# wanted by a target delays the target until it finishes, and this takes
# minutes). Re-run any time with `systemctl start xchan-demo` and read it with
# `journalctl -u xchan-demo`.
#
# Unit relationships this relies on (set in the target): each client's
# microvm@ unit is After/Wants/PartOf the server's. PartOf is one-way, so
# stopping a client touches nothing else, and Wants on an already-active server
# is a no-op, so starting a client does not restart the server. This unit is
# only After= the guests, no Requires/BindsTo, so stopping a client from
# inside ExecStart does not stop the demo.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.ghaf.reference.services.xchan-demo;
  inherit (lib)
    mkEnableOption
    mkOption
    mkIf
    types
    ;
  inherit (config.ghaf.networking) hosts;

  vms = [
    cfg.server
    cfg.teardownClient
    cfg.secondClient
  ];

  cidArray = lib.concatMapStringsSep " " (vm: "[${vm}]=${toString hosts.${vm}.cid}") vms;
  promptArray = lib.concatMapStringsSep " " (vm: "[${vm}]=${lib.escapeShellArg cfg.prompts.${vm}}") [
    cfg.teardownClient
    cfg.secondClient
  ];

  # Short alias (admin, net, client) and full name for every demo guest.
  aliasArray = lib.concatMapStringsSep " " (
    vm:
    let
      cid = toString hosts.${vm}.cid;
    in
    "[${lib.removeSuffix "-vm" vm}]=${cid} [${vm}]=${cid}"
  ) vms;
  cidList = lib.concatMapStringsSep " " (vm: "${vm}=${toString hosts.${vm}.cid}") vms;

  # Host console helper: run one command in a demo guest as root, always
  # bounded. Usable by the unprivileged console user: the bring-up key is a
  # world-readable store path (which is the BRING-UP ONLY part), and ssh only
  # needs a private 0600 copy of it.
  xchanGuest = pkgs.writeShellApplication {
    name = "xchan-guest";
    runtimeInputs = [
      pkgs.coreutils
      config.programs.ssh.package
    ];
    text = ''
      declare -A CID=(${aliasArray})
      usage() {
        echo "usage: xchan-guest <${
          lib.concatMapStringsSep "|" (vm: lib.removeSuffix "-vm" vm) vms
        }> '<command>'" >&2
        echo "  CIDs: ${cidList}; bounded by XCHAN_TIMEOUT (default 60 s)" >&2
        exit 2
      }
      [ "$#" -ge 2 ] || usage
      cid=''${CID[$1]:-}
      [ -n "$cid" ] || usage
      shift

      # Never unbounded: a hung guest ssh blocks the serial console's
      # foreground shell. 0 would mean "no limit" to timeout, so refuse it.
      t=''${XCHAN_TIMEOUT:-60}
      if ! [[ "$t" =~ ^[0-9]+$ ]] || ((10#$t == 0)); then
        t=60
      fi

      # Stage the key once per login session in the user's own runtime dir;
      # without one, in a private temp dir removed on exit.
      tmp=""
      if [ -n "''${XDG_RUNTIME_DIR:-}" ] && [ -d "$XDG_RUNTIME_DIR" ] && [ -O "$XDG_RUNTIME_DIR" ]; then
        key="$XDG_RUNTIME_DIR/xchan-bringup-key"
        if [ -L "$key" ] || [ ! -O "$key" ] || [ ! -s "$key" ]; then
          rm -f "$key"
          install -m 0600 ${cfg.sshKey} "$key"
        fi
      else
        tmp=$(mktemp -d)
        trap 'rm -rf "$tmp"' EXIT
        key="$tmp/key"
        install -m 0600 ${cfg.sshKey} "$key"
      fi

      timeout "$t" ssh -i "$key" \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o BatchMode=yes -o ConnectTimeout=8 -o LogLevel=ERROR \
        "root@vsock/$cid" "$@"
    '';
  };

  # Host console helper: every piece of demo evidence in one plain-text dump,
  # host first, then each guest (read from inside the guest). A guest that
  # does not answer prints UNREACHABLE and the report carries on.
  xchanDemoReport = pkgs.writeShellApplication {
    name = "xchan-demo-report";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.gnugrep
      config.systemd.package
      xchanGuest
    ];
    text = ''
      set +o errexit
      set +o pipefail

      section() { printf '\n==== %s ====\n' "$*"; }
      show() {
        if [ -n "$1" ]; then printf '%s\n' "$1"; else echo "(no matching lines)"; fi
      }
      # guest <alias> <command>: 255 is ssh failing to connect, 124 the
      # timeout; anything else is the command's own status (grep finding
      # nothing is 1) and its output is shown as is.
      guest() {
        local out rc
        out=$(XCHAN_TIMEOUT=''${XCHAN_TIMEOUT:-30} xchan-guest "$1" "$2" < /dev/null 2>&1)
        rc=$?
        if [ "$rc" -eq 255 ] || [ "$rc" -eq 124 ]; then
          echo "UNREACHABLE (exit $rc)"
          [ -z "$out" ] || printf '%s\n' "$out" | sed 's/^/  /'
        else
          show "$out"
        fi
      }

      echo "xchan demo report, $(date), host up $(cut -d. -f1 /proc/uptime)s"
      echo "CIDs: ${cidList}"

      section "host: journalctl -b -u xchan-demo | grep DEMO"
      show "$(journalctl -b -u xchan-demo --no-pager 2>&1 | grep DEMO)"

      section "host: journalctl -k -b | grep -E 'reclaim matrix|mailbox self-check|share self-check'"
      show "$(journalctl -k -b --no-pager 2>&1 | grep -E 'reclaim matrix|mailbox self-check|share self-check')"

      section "${cfg.server}: journalctl -b -u xchan-demo-server | tail -60"
      guest ${cfg.server} 'journalctl -b -u xchan-demo-server --no-pager | tail -60'

      section "${cfg.server}: journalctl -b -u xchan-demo-server-g2g | tail -40"
      guest ${cfg.server} 'journalctl -b -u xchan-demo-server-g2g --no-pager | tail -40'

      section "${cfg.server}: dmesg | grep pkvm-g2g"
      guest ${cfg.server} 'dmesg | grep pkvm-g2g'

      # Not -b: the demo tears ${cfg.teardownClient} down and boots it again,
      # so its steps 1-2 are in the previous guest boot (its journal is
      # persistent). journalctl marks each boot boundary.
      for vm in ${cfg.teardownClient} ${cfg.secondClient}; do
        section "$vm: journalctl -t xchan-demo-client (all boots kept, last 150 lines)"
        guest "$vm" 'journalctl -t xchan-demo-client --no-pager | tail -150'
        section "$vm: dmesg | grep pkvm-g2g"
        guest "$vm" 'dmesg | grep pkvm-g2g'
      done
      echo
      echo "==== end of report ===="
    '';
  };

  # BRING-UP ONLY. g2g-board-check: every board check of the guest-to-guest
  # work in one run, as PASS/FAIL lines. The transport checks need the
  # server guest's EL2 mailbox (one g2gchan process per VM) and its
  # xchan channels (one consumer each), so the demo's two servers are stopped
  # for them and started again at the end. Logs: /tmp/g2g-board-check.<pid>.
  g2gBoardCheck = pkgs.writeShellApplication {
    name = "g2g-board-check";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.gawk
      pkgs.gnugrep
      pkgs.gnused
      config.systemd.package
      xchanGuest
    ];
    text = ''
      set +o errexit
      set +o pipefail
      S=${cfg.server}
      A=${cfg.teardownClient}
      B=${cfg.secondClient}
      pass=0
      fail=0
      log=/tmp/g2g-board-check.$$
      mkdir -p "$log"
      ok() { echo "PASS  $*"; pass=$((pass + 1)); }
      bad() { echo "FAIL  $*"; fail=$((fail + 1)); }
      g() {
        local t=$1 vm=$2
        shift 2
        XCHAN_TIMEOUT=$t xchan-guest "$vm" "$@" < /dev/null 2>&1
      }
      # median of the numbers on stdin
      median() { sort -n | awk '{ v[NR] = $1 } END { if (NR) print v[int((NR + 1) / 2)]; else print "-" }'; }

      echo "g2g board check, $(date), host up $(cut -d. -f1 /proc/uptime)s, logs in $log"

      echo "-- EL2 (host kernel log)"
      k=$(journalctl -k -b --no-pager 2>&1)
      printf '%s\n' "$k" > "$log/kernel"
      for c in "reclaim matrix self-check" "mailbox self-check" "share self-check"; do
        line=$(grep "EL2 $c" "$log/kernel" | tail -1)
        if grep -q ": PASS" <<< "$line"; then ok "$line"; else bad "EL2 $c: $line"; fi
      done
      if grep -q "guest-to-guest DISABLED" "$log/kernel"; then
        bad "guest-to-guest DISABLED by the fail-closed gate"
      else
        ok "guest-to-guest enabled"
      fi

      echo "-- demo (host journal)"
      journalctl -b -u xchan-demo --no-pager > "$log/demo" 2>&1
      r=$(grep "DEMO RESULT" "$log/demo" | tail -1)
      if grep -q "DEMO RESULT PASS" <<< "$r"; then ok "demo: $r"; else bad "demo: $r"; fi
      # warm requests (req >= 2): time to first token over xchan (steps 1, 4, 6) and g2g (step 7)
      awk '/DEMO step=/ { split($0, a, "step="); split(a[2], b, " "); step = b[1] }
           /ttft_ms=/ && !/req=1 / { match($0, /ttft_ms=[0-9.]+/); t = substr($0, RSTART + 8, RLENGTH - 8)
             if (step == 7) print t > "'"$log"'/ttft-g2g"; else if (step == 1 || step == 4 || step == 6) print t > "'"$log"'/ttft-xchan" }' "$log/demo"
      echo "      llama time to first token, warm, median: xchan $(median < "$log/ttft-xchan" 2> /dev/null) ms, g2g $(median < "$log/ttft-g2g" 2> /dev/null) ms"

      echo "-- guests"
      for vm in "$S" "$A" "$B"; do
        m=$(g 30 "$vm" 'dmesg | grep pkvm-g2g')
        if grep -q "/dev/pkvm-g2g registered" <<< "$m"; then ok "$vm: /dev/pkvm-g2g registered"; else bad "$vm: $(grep '/dev/pkvm-g2g' <<< "$m" | head -1)"; fi
        if grep -q "runtime test off" <<< "$m"; then ok "$vm: runtime test off"; else bad "$vm: kernel runtime test not off"; fi
      done
      hi=$(g 30 "$S" pkvm-g2g-test self | sed -n 's/.*identity 0x\([0-9a-f]*\):.*/\1/p')
      if [ -n "$hi" ]; then ok "$S: identity 0x$hi"; else bad "$S: no guest-to-guest identity"; fi

      echo "-- transport (demo servers stopped meanwhile)"
      g 30 "$S" systemctl stop xchan-demo-server-g2g xchan-demo-server > /dev/null
      g 900 "$S" g2gc-echo server > "$log/echo-server" &
      sp=$!
      sleep 3
      g 900 "$A" g2gc-echo client "0x$hi" 20 > "$log/echo-client"
      wait "$sp"
      if grep -q "client: PASS" "$log/echo-client"; then
        ok "stream $A -> $S: $(grep 'client: PASS' "$log/echo-client" | sed 's/.*PASS //')"
      else
        bad "stream $A -> $S: $(tail -1 "$log/echo-client")"
      fi
      grep -hE "rtt|MB/s|cpu" "$log/echo-client" "$log/echo-server" | sed 's/^/      /'

      g 120 "$S" g2gc-echo server > "$log/vanish-server" &
      sp=$!
      sleep 3
      g 60 "$A" g2gc-echo vanish "0x$hi" > "$log/vanish-client"
      wait "$sp"
      vrc=$?
      if [ "$vrc" -eq 0 ] && grep -qE "went away \([1-9][0-9]* faulted" "$log/vanish-server"; then
        ok "vanish: $S survived $A dying mid-stream: $(grep 'went away' "$log/vanish-server" | sed 's/.*then //')"
      else
        bad "vanish: server exit $vrc: $(tail -1 "$log/vanish-server")"
      fi

      # transport only: the mock server answers at once (no model)
      for t in g2g xchan; do
        if [ "$t" = g2g ]; then ep="g2g:0x$hi"; sep=g2g; else ep=/dev/xchan0; sep=/dev/xchan0; fi
        g 200 "$S" timeout 120 "bench-mock-server-$t" -e "$sep" --ttft-ms 0 --itl-ms 0 > "$log/bench-server-$t" &
        sp=$!
        sleep 3
        g 200 "$A" "bench-client-$t" -e "$ep" -n 50 > "$log/bench-client-$t"
        kill "$sp" 2> /dev/null
        wait "$sp" 2> /dev/null
        if grep -q "ok=50 failed=0" "$log/bench-client-$t"; then
          ok "bench $t: $(grep 'TTFT (ms)' "$log/bench-client-$t")"
        else
          bad "bench $t: $(grep -E 'backend=|failed' "$log/bench-client-$t" | head -2 | tr '\n' ' ')"
        fi
        g 30 "$S" pkill -f "bench-mock-server-$t" > /dev/null
      done
      g 30 "$S" systemctl start xchan-demo-server xchan-demo-server-g2g > /dev/null

      echo "-- host after all of it"
      w=$(journalctl -k -b --no-pager 2>&1 | grep -iE 'WARNING|kept the guest page|Internal error|BUG:|Unhandled' | grep -vc ramoops)
      if [ "$w" -eq 0 ]; then ok "host kernel log: no warnings"; else bad "host kernel log: $w warning line(s)"; fi

      echo "g2g board check: $pass PASS, $fail FAIL"
      [ "$fail" -eq 0 ]
    '';
  };

  hostTools = pkgs.symlinkJoin {
    name = "xchan-demo-host-tools";
    paths = [
      xchanGuest
      xchanDemoReport
      g2gBoardCheck
    ];
  };

  orchestrator = pkgs.writeShellApplication {
    name = "xchan-demo";
    runtimeInputs = [
      pkgs.coreutils
      config.programs.ssh.package
      config.systemd.package
    ];
    text = ''
      # writeShellApplication turns on errexit; every failure here is handled
      # explicitly so it can name the step that failed.
      set +o errexit

      SERVER=${cfg.server}
      CLIENT_A=${cfg.teardownClient}
      CLIENT_B=${cfg.secondClient}
      N=${toString cfg.requests}
      # Read off config.ghaf.networking.hosts at build time, the central
      # allocation, not numbers remembered from an older image.
      declare -A CID=(${cidArray})
      declare -A PROMPT=(${promptArray})

      # The bring-up key lives world-readable in the store and ssh refuses a
      # private key that is not 0600, so stage a private copy.
      KEY="''${RUNTIME_DIRECTORY:-/run/xchan-demo}/id_ed25519"
      install -m 0600 ${cfg.sshKey} "$KEY"

      step=0
      say() { echo "DEMO $*"; }
      begin() {
        step=$1
        shift
        say "step=$step $*"
      }
      fail() {
        say "step=$step error: $*"
        say "RESULT FAIL step=$step"
        exit 1
      }

      # Every guest command goes through here: bounded, key-only, no host-key
      # state. `vsock/<cid>` is resolved by systemd-ssh-proxy via ssh_config.
      gssh() {
        local t=$1 vm=$2
        shift 2
        timeout "$t" ssh -i "$KEY" \
          -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
          -o BatchMode=yes -o LogLevel=ERROR \
          "root@vsock/''${CID[$vm]}" "$@"
      }

      # poll <seconds> <command...>: retry every 3 s until it succeeds or the
      # time is up.
      poll() {
        local deadline=$((SECONDS + $1))
        shift
        until "$@"; do
          if ((SECONDS >= deadline)); then
            return 1
          fi
          sleep 3
        done
      }

      vm_state() { systemctl show -p ActiveState --value "microvm@$1.service"; }
      vm_active() { [ "$(vm_state "$1")" = active ]; }
      vm_down() {
        case "$(vm_state "$1")" in
          inactive | failed) return 0 ;;
          *) return 1 ;;
        esac
      }
      vm_invocation() { systemctl show -p InvocationID --value "microvm@$1.service"; }
      guest_ready() { gssh 20 "$1" test -e /dev/xchan0 > /dev/null 2>&1; }
      server_ready() {
        gssh 20 "$SERVER" systemctl is-active --quiet xchan-demo-server.service > /dev/null 2>&1
      }
      g2g_restarts() {
        gssh 20 "$SERVER" systemctl show -p NRestarts --value xchan-demo-server-g2g.service 2> /dev/null
      }
      server_g2g_ready() {
        gssh 20 "$SERVER" systemctl is-active --quiet xchan-demo-server-g2g.service > /dev/null 2>&1
      }

      # Pass the guest's DEMO lines through unchanged (they name their client,
      # so the parallel step stays readable); indent anything else, tagged with
      # the guest, as context for a failure.
      relay() {
        local vm=$1 line
        while IFS= read -r line; do
          case "$line" in
            "DEMO "*) printf '%s\n' "$line" ;;
            *) printf '    %s| %s\n' "$vm" "$line" ;;
          esac
        done
      }

      # run_client <vm> <n> [extra client args...]
      # Runs xchan-demo-client through the guest's xchan-demo-run wrapper,
      # which also records every line in the guest's own journal. The client
      # is bounded inside the guest too, so a hung WAIT_CHANNEL cannot outlive
      # the ssh session that started it. Never --show-text: whatever the
      # client prints ends up in this (host) journal.
      run_client() {
        local vm=$1 n=$2 cmd rc
        shift 2
        cmd=$(printf '%q ' timeout ${toString cfg.clientTimeoutSeconds} \
          xchan-demo-run -e /dev/xchan0 --name "$vm" \
          --key /etc/xchan-demo/identity.seed \
          --server-pk /etc/xchan-demo/server.pk \
          -n "$n" -p "''${PROMPT[$vm]}" "$@")
        gssh ${toString (cfg.clientTimeoutSeconds + 30)} "$vm" \
          "export PATH=/run/current-system/sw/bin:\$PATH; $cmd" 2>&1 | relay "$vm"
        rc=''${PIPESTATUS[0]}
        if [ "$rc" -ne 0 ]; then
          say "vm=$vm client exited $rc"
        fi
        return "$rc"
      }

      ensure_up() {
        local vm=$1
        if vm_down "$vm"; then
          say "step=$step microvm@$vm is $(vm_state "$vm"); starting it"
          timeout 300 systemctl start "microvm@$vm.service" ||
            fail "systemctl start microvm@$vm failed"
        fi
        poll ${toString cfg.guestWaitSeconds} vm_active "$vm" ||
          fail "microvm@$vm not active after ${toString cfg.guestWaitSeconds}s (state: $(vm_state "$vm"))"
      }

      say "start server=$SERVER(cid ''${CID[$SERVER]}) clients=$CLIENT_A(cid ''${CID[$CLIENT_A]}),$CLIENT_B(cid ''${CID[$CLIENT_B]}) requests=$N"

      begin 0 "waiting for $SERVER, $CLIENT_A and $CLIENT_B"
      for vm in "$SERVER" "$CLIENT_A" "$CLIENT_B"; do
        ensure_up "$vm"
      done
      for vm in "$CLIENT_A" "$CLIENT_B"; do
        poll ${toString cfg.guestWaitSeconds} guest_ready "$vm" ||
          fail "$vm not reachable over vsock with /dev/xchan0 after ${toString cfg.guestWaitSeconds}s"
      done
      poll ${toString cfg.guestWaitSeconds} server_ready ||
        fail "xchan-demo-server not active in $SERVER after ${toString cfg.guestWaitSeconds}s"
      server_run=$(vm_invocation "$SERVER")

      begin 1 "$CLIENT_A: $N encrypted requests"
      run_client "$CLIENT_A" "$N" || fail "$CLIENT_A requests failed"

      begin 2 "$CLIENT_A: close a channel; the closed one must error, a fresh one must work"
      # --close-reopen ignores -n and always runs exactly 2 requests.
      run_client "$CLIENT_A" 2 --close-reopen ||
        fail "$CLIENT_A close/reopen failed"

      begin 3 "tearing down $CLIENT_A (systemctl stop microvm@$CLIENT_A)"
      timeout 120 systemctl stop "microvm@$CLIENT_A.service" ||
        say "step=3 systemctl stop returned non-zero; checking state"
      poll 60 vm_down "$CLIENT_A" ||
        fail "microvm@$CLIENT_A still $(vm_state "$CLIENT_A") after stop"
      say "step=3 $CLIENT_A is $(vm_state "$CLIENT_A"); $SERVER is $(vm_state "$SERVER"); $CLIENT_B is $(vm_state "$CLIENT_B")"
      vm_active "$SERVER" || fail "stopping $CLIENT_A took $SERVER down"
      vm_active "$CLIENT_B" || fail "stopping $CLIENT_A took $CLIENT_B down"

      begin 4 "$CLIENT_B: $N encrypted requests while $CLIENT_A is gone"
      run_client "$CLIENT_B" "$N" || fail "$CLIENT_B requests failed"

      begin 5 "bringing $CLIENT_A back (systemctl start microvm@$CLIENT_A)"
      timeout 300 systemctl start "microvm@$CLIENT_A.service" ||
        fail "systemctl start microvm@$CLIENT_A failed"
      poll ${toString cfg.guestWaitSeconds} guest_ready "$CLIENT_A" ||
        fail "$CLIENT_A not reachable over vsock with /dev/xchan0 after ${toString cfg.guestWaitSeconds}s"
      [ "$(vm_invocation "$SERVER")" = "$server_run" ] ||
        fail "$SERVER was restarted while $CLIENT_A came back"

      begin 6 "$CLIENT_A and $CLIENT_B in parallel, $N encrypted requests each"
      run_client "$CLIENT_A" "$N" &
      pa=$!
      run_client "$CLIENT_B" "$N" &
      pb=$!
      wait "$pa"
      ra=$?
      wait "$pb"
      rb=$?
      if [ "$ra" -ne 0 ] || [ "$rb" -ne 0 ]; then
        fail "parallel requests: $CLIENT_A exited $ra, $CLIENT_B exited $rb"
      fi
      [ "$(vm_invocation "$SERVER")" = "$server_run" ] ||
        fail "$SERVER was restarted during the demo"

      begin 7 "$CLIENT_A and $CLIENT_B over guest-to-guest shared memory (g2g), $N encrypted requests each"
      poll ${toString cfg.guestWaitSeconds} server_g2g_ready ||
        fail "xchan-demo-server-g2g not active in $SERVER after ${toString cfg.guestWaitSeconds}s"
      # The host names the server VM to the clients; that is no trust: each
      # client checks the server's pinned key, so a wrong name fails the
      # handshake.
      server_hi=$(gssh 30 "$SERVER" pkvm-g2g-test self 2> /dev/null |
        sed -n 's/.*identity 0x\([0-9a-f]*\):.*/\1/p')
      [ -n "$server_hi" ] || fail "could not read $SERVER's guest-to-guest identity"
      g2g_runs=$(g2g_restarts)
      # run_client's own -e /dev/xchan0 comes first; the client takes the last -e.
      run_client "$CLIENT_A" "$N" -e "g2g:0x$server_hi" || fail "$CLIENT_A over g2g failed"
      run_client "$CLIENT_B" "$N" -e "g2g:0x$server_hi" || fail "$CLIENT_B over g2g failed"
      # An orderly close over g2g, then a fresh channel (2 requests).
      run_client "$CLIENT_A" 2 --close-reopen -e "g2g:0x$server_hi" ||
        fail "$CLIENT_A --close-reopen over g2g failed"
      [ "$(g2g_restarts)" = "$g2g_runs" ] ||
        fail "xchan-demo-server-g2g restarted during step 7 (NRestarts $g2g_runs -> $(g2g_restarts))"
      [ "$(vm_invocation "$SERVER")" = "$server_run" ] ||
        fail "$SERVER was restarted during the demo"

      begin 8 "$CLIENT_A torn down while a g2g channel to $SERVER is live (EL2 dismantles its shares)"
      # g2gc-echo needs the server guest's one-slot mailbox to itself.
      gssh 30 "$SERVER" systemctl stop xchan-demo-server-g2g.service
      gssh 300 "$SERVER" g2gc-echo server > /tmp/xchan-demo-step8-server.log 2>&1 &
      sp=$!
      sleep 3
      gssh 300 "$CLIENT_A" g2gc-echo client "0x$server_hi" 100000 > /tmp/xchan-demo-step8-client.log 2>&1 &
      cp=$!
      sleep 5
      timeout 300 systemctl stop "microvm@$CLIENT_A.service" ||
        fail "systemctl stop microvm@$CLIENT_A failed"
      wait "$sp"
      src=$?
      # The client's ssh died with its VM; do not wait out its timeout.
      kill "$cp" 2> /dev/null
      wait "$cp"
      relay "$SERVER" < /tmp/xchan-demo-step8-server.log
      # A faulted read proves EL2 took the dying VM's share away under the
      # server (an orderly close never faults).
      if [ "$src" -ne 0 ] || ! grep -qE "went away \([1-9][0-9]* faulted" /tmp/xchan-demo-step8-server.log; then
        fail "$SERVER's g2gc-echo did not end cleanly when $CLIENT_A was torn down (exit $src)"
      fi
      timeout 300 systemctl start "microvm@$CLIENT_A.service" ||
        fail "systemctl start microvm@$CLIENT_A failed"
      poll ${toString cfg.guestWaitSeconds} guest_ready "$CLIENT_A" ||
        fail "$CLIENT_A not reachable over vsock with /dev/xchan0 after ${toString cfg.guestWaitSeconds}s"
      gssh 30 "$SERVER" systemctl start xchan-demo-server-g2g.service
      [ "$(vm_invocation "$SERVER")" = "$server_run" ] ||
        fail "$SERVER was restarted during the demo"

      say "RESULT PASS"
    '';
  };
in
{
  _file = ./xchan-demo.nix;

  options.ghaf.reference.services.xchan-demo = {
    enable = mkEnableOption "the host-side orchestrator of the encrypted guest-to-guest LLM demo (BRING-UP ONLY)";

    server = mkOption {
      type = types.str;
      default = "admin-vm";
      description = "The model guest (xchan listener running xchan-demo-server).";
    };

    teardownClient = mkOption {
      type = types.str;
      default = "net-vm";
      description = "The client that asks first, is torn down, and comes back.";
    };

    secondClient = mkOption {
      type = types.str;
      default = "client-vm";
      description = "The client that asks while the first one is gone.";
    };

    sshKey = mkOption {
      type = types.path;
      description = ''
        Private key that logs in as root on every demo guest over vsock. A copy
        is staged 0600 at run time, so a world-readable store path is accepted,
        which is exactly why this is BRING-UP ONLY.
      '';
    };

    requests = mkOption {
      type = types.ints.positive;
      default = 3;
      description = "Encrypted requests per client in steps 1, 4 and 6.";
    };

    prompts = mkOption {
      type = types.attrsOf types.str;
      default = {
        net-vm = "Say hello in one short sentence.";
        client-vm = "Name one colour of the rainbow in one short sentence.";
      };
      description = ''
        Prompt per client guest. NOT secret from the host: it is passed on the
        host-side ssh command line, so keep it neutral.
      '';
    };

    startDelay = mkOption {
      type = types.str;
      default = "60s";
      description = ''
        OnBootSec of the timer that runs the demo once per boot. The script
        itself waits (bounded) for the guests, so this only keeps it from
        polling through the earliest part of boot.
      '';
    };

    guestWaitSeconds = mkOption {
      type = types.ints.positive;
      default = 600;
      description = "Bound on each wait for a guest, its vsock login, or the demo server.";
    };

    clientTimeoutSeconds = mkOption {
      type = types.ints.positive;
      default = 300;
      description = ''
        Bound on one xchan-demo-client run (enforced in the guest and, plus
        slack, on the host). Keep it above the client's own worst case,
        220 s of bounded waits plus reply streaming, see the time budget in
        demo_client.c, or a run cut short loses its final `ok= failed=` line.
      '';
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = lib.all (vm: hosts ? ${vm}) vms;
        message = "ghaf.reference.services.xchan-demo: every demo guest (${lib.concatStringsSep ", " vms}) must be a VM with a CID in ghaf.networking.hosts.";
      }
      {
        assertion = lib.all (vm: cfg.prompts ? ${vm}) [
          cfg.teardownClient
          cfg.secondClient
        ];
        message = "ghaf.reference.services.xchan-demo.prompts needs an entry for each client.";
      }
    ];

    # xchan-guest, xchan-demo-report and g2g-board-check, for the host console.
    environment.systemPackages = [ hostTools ];

    systemd.services.xchan-demo = {
      description = "encrypted guest-to-guest LLM demo orchestrator (bring-up only)";
      # Ordering only. Requires/BindsTo/PartOf would make step 3 (stopping a
      # client guest) stop this unit too.
      after = map (vm: "microvm@${vm}.service") vms;
      serviceConfig = {
        Type = "oneshot";
        ExecStart = lib.getExe orchestrator;
        RuntimeDirectory = "xchan-demo";
        RuntimeDirectoryMode = "0700";
        # Every step is bounded on its own; this is the backstop.
        TimeoutStartSec = "60min";
        SyslogIdentifier = "xchan-demo";
      };
    };

    systemd.timers.xchan-demo = {
      description = "run the encrypted guest-to-guest LLM demo once per boot";
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = cfg.startDelay;
        AccuracySec = "1s";
      };
    };
  };
}
