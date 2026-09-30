#!/bin/sh
# =============================================================================
# tests/smoke.sh - teste de fumaca do wg-client-manager.sh
# Uso: sudo sh tests/smoke.sh   (roda tambem no CI, em containers de varias distros)
#
# Seguranca por Design: trabalha apenas em diretorios temporarios (WG_DIR e
# WG_LOG_DIR isolados), nao cria interfaces, nao sobe tuneis e nao altera rede.
# =============================================================================
set -u
umask 077

SCRIPT="${1:-./wg-client-manager.sh}"
TMP=$(mktemp -d)
export WG_DIR="$TMP/wireguard" WG_LOG_DIR="$TMP/log"
trap 'rm -rf "$TMP"' EXIT
FAIL=0

ok()   { printf '[PASS] %s\n' "$1"; }
fail() { printf '[FAIL] %s\n' "$1"; FAIL=1; }

expect_rc() { # rc_esperado descricao comando...
    _exp=$1; _desc=$2; shift 2
    "$@" >"$TMP/out" 2>&1; _rc=$?
    if [ "$_rc" -eq "$_exp" ]; then ok "$_desc (rc=$_rc)"; else fail "$_desc (rc=$_rc, esperado $_exp)"; cat "$TMP/out"; fi
}

SPUB=$(wg genkey | wg pubkey)
wg genpsk > "$TMP/psk"

BASE="--create --name wg-teste --endpoint vpn.exemplo.com.br:51820 --server-pubkey $SPUB --address 10.8.0.2/32 --server-tunnel-ip 10.8.0.1 --psk-file $TMP/psk --keepalive 25"

expect_rc 0 "--version" sh "$SCRIPT" --version
expect_rc 0 "--help"    sh "$SCRIPT" --help
expect_rc 1 "--psk como argumento e recusado" sh "$SCRIPT" --create --psk abc
expect_rc 1 "endpoint invalido e recusado" sh "$SCRIPT" --create --name t1 --endpoint 999.1.1.1:51820 \
    --server-pubkey "$SPUB" --address 10.8.0.2/32 --allowed-ips 10.0.0.0/24
expect_rc 1 "nome de tunel invalido e recusado" sh "$SCRIPT" --create --name "WG Teste" --endpoint 10.0.0.1 \
    --server-pubkey "$SPUB" --address 10.8.0.2/32 --allowed-ips 10.0.0.0/24

# check "descricao" comando... -> PASS/FAIL conforme o codigo de saida
check() { _d=$1; shift; if "$@"; then ok "$_d"; else fail "$_d"; fi; }
# shellcheck disable=SC2329  # invocadas indiretamente via check()
has()   { printf '%s\n' "$1" | grep -q "$2"; }
# shellcheck disable=SC2329
same()  { [ -n "$1" ] && [ "$1" = "$2" ]; }
perm()  { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"; }

# shellcheck disable=SC2086
OUT1=$(sh "$SCRIPT" $BASE --allowed-ips "192.168.10.0/24,10.0.10.0/24" 2>&1)
check "criacao retorna STATUS=changed" has "$OUT1" '^STATUS=changed'

# shellcheck disable=SC2086
OUT2=$(sh "$SCRIPT" $BASE --allowed-ips "192.168.10.0/24, 10.0.10.0/24" 2>&1)
check "idempotencia: STATUS=unchanged" has "$OUT2" '^STATUS=unchanged'

# shellcheck disable=SC2086
OUT3=$(sh "$SCRIPT" $BASE --allowed-ips "192.168.10.0/24,10.0.10.0/24,10.0.20.0/24" --mtu 1380 2>&1)
check "alteracao retorna STATUS=changed" has "$OUT3" '^STATUS=changed'

PUB1=$(printf '%s\n' "$OUT1" | sed -n 's/^PUBKEY=//p')
PUB3=$(printf '%s\n' "$OUT3" | sed -n 's/^PUBKEY=//p')
check "chave privada preservada na atualizacao" same "$PUB1" "$PUB3"

_bk=""
for _b in "$WG_DIR"/wg-teste/.backup/*-antes-cli-update; do [ -d "$_b" ] && _bk=$_b; done
check "backup criado antes da atualizacao" [ -n "$_bk" ]

CONF="$WG_DIR/wg-teste/wg-teste.conf"
check "par de chaves consistente" same "$(wg pubkey < "$WG_DIR/wg-teste/privatekey")" "$PUB1"
check ".conf aceito pelo wg-quick" sh -c "wg-quick strip '$CONF' >/dev/null 2>&1"
check "IP do servidor no tunel incluido como /32" grep -q '^AllowedIPs = .*10.8.0.1/32' "$CONF"
check "MTU gravado" grep -q '^MTU = 1380' "$CONF"
check "permissao do .conf = 600" [ "$(perm "$CONF")" = "600" ]
check "permissao da pasta do tunel = 700" [ "$(perm "$WG_DIR/wg-teste")" = "700" ]

printf '\n'
if [ "$FAIL" -eq 0 ]; then echo "RESULTADO: todos os testes passaram"; else echo "RESULTADO: FALHAS encontradas"; fi
exit "$FAIL"
