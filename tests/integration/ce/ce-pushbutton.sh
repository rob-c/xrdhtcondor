#!/bin/bash
# Push-button: mint one WLCG token, try every reachable HTCondor-CE with it, and
# leave a report. Approve the device code it prints in a browser; nothing else.
#
#   bash ~/ce-pushbutton.sh            # ask for the p12 passphrase, mint, test
#   bash ~/ce-pushbutton.sh --no-mint  # only test the tokens already here
#   bash ~/ce-pushbutton.sh --no-proxy # skip refreshing the proxy
#
# Everything lands in ~/ce-report-<stamp>/ — hand that directory back, it holds no secrets.
set -u
BIN="$HOME/venv-grid/bin"
STAMP=$(date +%Y%m%d-%H%M%S)
OUT="$HOME/ce-report-$STAMP"
LOG="$OUT/report.txt"
CES=(condorce01.cern.ch ce503.cern.ch ce15.pic.es htcondor-ce-1-kit.gridka.de
     hepcondor.ph.liv.ac.uk lcgce02.phy.bris.ac.uk htc01.ppgrid1.rhul.ac.uk)
MINT=yes
PROXY=yes
while [ $# -gt 0 ]; do
  case "$1" in
    --no-mint) MINT=no ;;
    --no-proxy) PROXY=no ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

mkdir -p "$OUT" "$HOME/.condor/tokens.d"
say() { printf '%s\n' "$*" | tee -a "$LOG"; }

say "== report: $OUT"
say "== $(date)"
say "== host: $(uname -sm), $("$BIN/python" -V 2>&1)"
say "== $("$BIN/xrdhtcondor" --version 2>&1) / $("$BIN/xrd-auth" --version 2>&1)"

# One fresh proxy first: it costs one password and is the credential every
# fallback path needs. It prompts here, which is why this script wants a terminal.
BUNDLE=$(ls "$HOME"/*.p12 2>/dev/null | head -1)
if [ "$PROXY" = yes ] && [ -n "$BUNDLE" ]; then
  say ""
  say "== refreshing the proxy from $(basename "$BUNDLE") - your PKCS#12 passphrase"
  if "$BIN/xrd-auth" init -p12 "$BUNDLE" -voms lhcb -valid 24:00 -out "$HOME/.x509up" 2>&1 | tee -a "$LOG"; then
    say "   proxy: $("$BIN/xrd-auth" info -file "$HOME/.x509up" -timeleft 2>&1)"
  else
    say "   (proxy not refreshed - carrying on with whatever is there)"
  fi
fi

try_all() {
  local token="$1" label="$2" accepted=0 out code
  say ""
  say "== offering '$label' to ${#CES[@]} CEs"
  for ce in "${CES[@]}"; do
    local args=(auth --host "$ce" --sock collector)
    [ -n "$token" ] && args+=(--token "$token")
    out=$(timeout 70 "$BIN/xrdhtcondor" "${args[@]}" 2>&1); code=$?
    if [ $code -eq 0 ]; then
      say "   ACCEPTED  $ce"
      say "             $out"
      accepted=$((accepted + 1))
    else
      say "   refused   $ce :: $(printf '%s' "$out" | tail -1 | cut -c1-140)"
    fi
  done
  say "   -> $accepted of ${#CES[@]} accepted '$label'"
  [ "$accepted" -gt 0 ]
}

if [ "$MINT" = no ]; then
  say ""
  say "== tokens already here"
  "$BIN/xrdhtcondor" auth --host placeholder --list 2>&1 | tee -a "$LOG"
  if try_all "" "the tokens already here"; then exit 0; fi
  say ""
  say "Nothing accepted. Re-run without --no-mint to mint a fresh token."
  exit 1
fi

say ""
say "=================================================================="
say "== minting a WLCG token (the WLCG reference IAM, default audience)"
say "   Open the URL below, sign in with CERN SSO, approve the code."
say "   The script waits; when it moves on, the token exists."
say "=================================================================="
file="$HOME/.condor/tokens.d/ce-$STAMP"
if ! "$BIN/xrd-auth" token init --provider wlcg --flow device --out "$file" 2>&1 | tee -a "$LOG"; then
  say "   minting failed - if the page said 'token not found', the code expired:"
  say "   device codes last a few minutes, so just run this script again."
  say "== report: $OUT"
  exit 1
fi
"$BIN/xrd-auth" token info "$file" 2>&1 | tee -a "$LOG"

if try_all "$file" "the WLCG reference IAM"; then
  say ""
  say "== a CE accepted this token. It is $file"
  say "== report: $OUT"
  exit 0
fi

say ""
say "== No CE accepted a token from the WLCG reference IAM."
say "== The audience is not the gate: the WLCG default and a CE's own name were"
say "==   both refused by all seven (report of 12:34), so the gate is the issuer -"
say "==   these sites trust other issuers."
say "== What would change the answer:"
say "==   * LHCb's IAM (https://lhcb-auth.cern.ch) - a public client must be"
say "==     registered there first, by LHCb computing;"
say "==   * CERN SSO (https://auth.cern.ch) - a client registered there;"
say "==   * or a site that adds the WLCG IAM to its trusted issuers."
say "==   Then:  xrd-auth token init --provider <issuer> --flow device --out <file>"
say "==          bash ~/ce-pushbutton.sh --no-mint --token-off  (or --no-mint)"
say "== Nothing else in this client is waiting on it."
say "== report: $OUT  -- hand this directory back; it holds no secrets."
exit 1
