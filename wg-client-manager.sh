#!/bin/sh
# =============================================================================
# wg-client-manager.sh
# Versao    : 1.6.2 (2026-09-29)
# Projeto   : EdenCore - Comunidade de Infraestrutura de TI
# Instrutor : Daniel Selbach Figueiró
# Funcao    : criar e gerenciar clientes WireGuard (wg-quick) via menu interativo.
#
# Transparencia: este script foi desenvolvido com auxilio de IA (Claude, da
# Anthropic). O codigo foi revisado, testado e validado pelo instrutor antes
# da publicacao.
#
# Licenca   : MIT (arquivo LICENSE)
# Historico : CHANGELOG.md
# Integridade: confira o SHA256 publicado em cada release antes de executar.
#
# Modo nao interativo: sh wg-client-manager.sh --help
#
# Seguranca por Design:
#   - Executa somente como root; umask 077 em todo o fluxo (pastas 700, arquivos 600).
#   - Private key gerada localmente com "wg genkey", nunca exibida na tela.
#   - PSK e gerada no SERVIDOR; aqui e apenas colada (sem eco) e gravada em arquivo 600.
#   - Toda entrada (nome, IP, CIDR, porta, chave, DNS) e validada antes de gravar.
#   - Segredos nunca passam como argumento de comando externo (invisiveis ao "ps").
#   - Opcao de exibir .conf com chaves ocultas para envio a suporte.
#   - Nao altera firewall, ip_forward nem NAT do host (menor privilegio).
#   - Remocao de tunel exige confirmacao digitando o nome exato.
#
# Estrutura gerada por tunel:
#   /etc/wireguard/<tunel>/privatekey      (600)
#   /etc/wireguard/<tunel>/publickey       (600)
#   /etc/wireguard/<tunel>/presharedkey    (600, somente se usada)
#   /etc/wireguard/<tunel>/<tunel>.conf    (600)
#   /etc/wireguard/<tunel>.conf -> <tunel>/<tunel>.conf  (symlink p/ wg-quick e wg-quick@)
#
# Compatibilidade: POSIX sh (bash, dash, ash/busybox).
# Gerenciadores  : apt-get, dnf, yum, zypper, pacman, apk, xbps-install, emerge.
# Init           : systemd e OpenRC (habilitar no boot).
#
# Uso: sudo sh wg-client-manager.sh
# =============================================================================

# shellcheck disable=SC2154,SC2153,SC1091  # vars atribuidas via eval; os-release lido em runtime
set -u
umask 077
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

VERSION="1.6.2"
WG_DIR="${WG_DIR:-/etc/wireguard}"
LOG_DIR="${WG_LOG_DIR:-/var/log/wg-client-manager}"
DYN_CTRL="/sys/kernel/debug/dynamic_debug/control"
DEBUG_ACTIVE=0
SETTINGS_FILE="/etc/wg-client-manager.conf"
AGENT_BIN="/usr/local/sbin/wg-client-manager"
UNIT_DIR="/etc/systemd/system"
UNIT_NAME="wg-client-manager-maint"
if [ -d /run ]; then RUN_DIR="/run/wg-client-manager"; else RUN_DIR="/var/run/wg-client-manager"; fi
LOCK_DIR="$RUN_DIR/maint.lock"
LOCK_HELD=0
BACKUP_KEEP=5
MTU=""

# ----------------------------------------------------------------------------
# Saida
# ----------------------------------------------------------------------------
if [ -t 1 ]; then
    C_R=$(printf '\033[31m'); C_G=$(printf '\033[32m')
    C_Y=$(printf '\033[33m'); C_B=$(printf '\033[36m'); C_N=$(printf '\033[0m')
else
    C_R=""; C_G=""; C_Y=""; C_B=""; C_N=""
fi

msg_ok()   { printf '%s[OK]%s %s\n'    "$C_G" "$C_N" "$1"; }
msg_err()  { printf '%s[ERRO]%s %s\n'  "$C_R" "$C_N" "$1" >&2; }
msg_warn() { printf '%s[AVISO]%s %s\n' "$C_Y" "$C_N" "$1"; }
msg_info() { printf '%s[INFO]%s %s\n'  "$C_B" "$C_N" "$1"; }

restore_tty() { stty echo 2>/dev/null || true; }

# Debug do kernel nunca fica ligado por esquecimento: desligado em qualquer saida.
debug_off() {
    if [ "$DEBUG_ACTIVE" -eq 1 ] && [ -e "$DYN_CTRL" ]; then
        echo 'module wireguard -p' > "$DYN_CTRL" 2>/dev/null
    fi
    DEBUG_ACTIVE=0
}
# Estado de testes controlados: desfeito em qualquer saida do script.
TEST_ROUTE=""; TEST_ROUTE_FAM=""; TEST_EP_TUN=""; TEST_EP_PEER=""; TEST_EP_ORIG=""
test_cleanup() {
    if [ -n "$TEST_ROUTE" ]; then
        ip "$TEST_ROUTE_FAM" route del blackhole "$TEST_ROUTE" 2>/dev/null
        TEST_ROUTE=""
    fi
    if [ -n "$TEST_EP_TUN" ] && [ -n "$TEST_EP_ORIG" ]; then
        wg set "$TEST_EP_TUN" peer "$TEST_EP_PEER" endpoint "$TEST_EP_ORIG" 2>/dev/null
        TEST_EP_TUN=""
    fi
}

release_lock() {
    if [ "$LOCK_HELD" -eq 1 ]; then rm -rf "$LOCK_DIR"; LOCK_HELD=0; fi
}
trap 'test_cleanup; debug_off; release_lock' EXIT
trap 'restore_tty; test_cleanup; debug_off; release_lock; printf "\n"; exit 130' INT TERM

pause() {
    printf '\nPressione Enter para continuar...'
    read -r _p || true
}

# ask VAR "Pergunta" [padrao]  -> le linha e grava em VAR
ask() {
    printf '%s' "$2"
    [ -n "${3:-}" ] && printf ' [%s]' "$3"
    printf ': '
    IFS= read -r _ans || { printf '\n'; msg_err "Entrada encerrada."; exit 1; }
    [ -z "$_ans" ] && _ans=${3:-}
    eval "$1=\$_ans"
}

# ask_secret VAR "Pergunta"  -> leitura sem eco
ask_secret() {
    printf '%s: ' "$2"
    stty -echo 2>/dev/null
    IFS= read -r _ans || _ans=""
    restore_tty
    printf '\n'
    eval "$1=\$_ans"
}

confirm() {
    ask _c "$1 [s/N]"
    case "$_c" in s|S|sim|SIM|y|Y) return 0 ;; *) return 1 ;; esac
}

# ----------------------------------------------------------------------------
# Validacoes
# ----------------------------------------------------------------------------
# Nome do tunel: minusculas, numeros, "-" e "_", inicia com letra, max 15
# (limite IFNAMSIZ do kernel Linux; compativel com wg-quick e systemd).
valid_tunnel_name() {
    printf '%s' "$1" | grep -Eq '^[a-z][a-z0-9_-]{0,14}$'
}

valid_port() {
    case "$1" in ''|*[!0-9]*|0*) return 1 ;; esac
    [ "${#1}" -le 5 ] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

valid_keepalive() {
    [ "$1" = "0" ] && return 0
    valid_port "$1"
}

valid_ipv4() {
    printf '%s' "$1" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$' || return 1
    _ifs4=$IFS; IFS=.
    # shellcheck disable=SC2086
    set -- $1
    IFS=$_ifs4
    for _oct in "$@"; do
        case "$_oct" in 0?*) return 1 ;; esac
        [ "$_oct" -le 255 ] || return 1
    done
    return 0
}

valid_ipv6() {
    [ "${#1}" -le 45 ] || return 1
    printf '%s' "$1" | grep -Eq '^[0-9A-Fa-f:.]+$' || return 1
    case "$1" in *:*) ;; *) return 1 ;; esac
    case "$1" in *:::*) return 1 ;; esac
    _rest=${1#*::}
    if [ "$_rest" != "$1" ]; then
        case "$_rest" in *::*) return 1 ;; esac
    fi
    return 0
}

valid_ip() { valid_ipv4 "$1" || valid_ipv6 "$1"; }

valid_cidr() {
    case "$1" in */*) ;; *) return 1 ;; esac
    _addr=${1%/*}; _pfx=${1##*/}
    case "$_pfx" in ''|*[!0-9]*|0?*) return 1 ;; esac
    if valid_ipv4 "$_addr"; then
        [ "$_pfx" -le 32 ]
    elif valid_ipv6 "$_addr"; then
        [ "$_pfx" -le 128 ]
    else
        return 1
    fi
}

valid_fqdn() {
    [ "${#1}" -le 253 ] || return 1
    printf '%s' "$1" | grep -Eq '^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$'
}

# Chave WireGuard: base64 de 32 bytes (44 caracteres terminando em "=")
valid_wgkey() {
    printf '%s' "$1" | grep -Eq '^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$'
}

# normalize_list "a, b,c" validador -> imprime "a, b, c" ou retorna 1
normalize_list() {
    _raw=$(printf '%s' "$1" | tr -d ' \t')
    [ -n "$_raw" ] || return 1
    case "$_raw" in ,*|*,|*,,*) return 1 ;; esac
    _out=""
    _ifsl=$IFS; IFS=,; set -f
    for _item in $_raw; do
        if ! "$2" "$_item"; then
            IFS=$_ifsl; set +f
            return 1
        fi
        case ", $_out, " in *", $_item, "*) continue ;; esac
        _out="${_out:+$_out, }$_item"
    done
    IFS=$_ifsl; set +f
    printf '%s' "$_out"
}

# ----------------------------------------------------------------------------
# Deteccao de ambiente
# ----------------------------------------------------------------------------
require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        msg_err "Execute como root: sudo sh $0"
        exit 1
    fi
}

wg_installed() {
    command -v wg >/dev/null 2>&1 && command -v wg-quick >/dev/null 2>&1
}

kernel_support() {
    [ -d /sys/module/wireguard ] && return 0
    modprobe wireguard >/dev/null 2>&1 && return 0
    command -v wireguard-go >/dev/null 2>&1 && return 0
    return 1
}

init_system() {
    if [ -d /run/systemd/system ]; then
        printf 'systemd'
    elif command -v rc-update >/dev/null 2>&1; then
        printf 'openrc'
    else
        printf 'desconhecido'
    fi
}

detect_pm() {
    for _pm in apt-get dnf yum zypper pacman apk xbps-install emerge; do
        if command -v "$_pm" >/dev/null 2>&1; then
            printf '%s' "$_pm"
            return 0
        fi
    done
    return 1
}

tunnel_exists() {
    [ -f "$WG_DIR/$1/$1.conf" ]
}

tunnel_is_up() {
    ip link show "$1" >/dev/null 2>&1
}

check_install() {
    printf '\n--- Verificacao do ambiente ---\n'
    if [ -r /etc/os-release ]; then
        _os=$(. /etc/os-release && printf '%s' "${PRETTY_NAME:-$ID}")
        msg_info "Sistema: $_os | Kernel: $(uname -r) | Init: $(init_system)"
    fi

    if command -v wg >/dev/null 2>&1; then msg_ok "wg encontrado: $(command -v wg)"
    else msg_err "wg NAO encontrado."; fi

    if command -v wg-quick >/dev/null 2>&1; then msg_ok "wg-quick encontrado: $(command -v wg-quick)"
    else msg_err "wg-quick NAO encontrado."; fi

    if command -v ip >/dev/null 2>&1; then msg_ok "iproute2 (ip) encontrado."
    else msg_err "comando ip NAO encontrado."; fi

    if kernel_support; then msg_ok "Suporte WireGuard no kernel (ou wireguard-go) disponivel."
    else msg_warn "Modulo wireguard indisponivel. Kernel < 5.6 exige wireguard-dkms ou wireguard-go."; fi

    msg_info "Firewall local: $(detect_firewall)"
    if command -v resolvconf >/dev/null 2>&1; then msg_ok "resolvconf encontrado (diretiva DNS funcional)."
    else msg_warn "resolvconf ausente: tuneis com DNS vao falhar no wg-quick."; fi

    if ! wg_installed; then
        printf '\n'
        msg_warn "WireGuard NAO instalado. Use a opcao 2 do menu para instalar."
    fi
}

# ----------------------------------------------------------------------------
# Instalacao
# ----------------------------------------------------------------------------
install_resolvconf() {
    command -v resolvconf >/dev/null 2>&1 && return 0

    # Com systemd-resolved ativo, usa o modo de compatibilidade do resolvectl
    # em vez de instalar openresolv (evita conflito no /etc/resolv.conf).
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        if [ "$1" = "apt-get" ]; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y systemd-resolved >/dev/null 2>&1 || true
        fi
        if ! command -v resolvconf >/dev/null 2>&1 && command -v resolvectl >/dev/null 2>&1; then
            ln -sf "$(command -v resolvectl)" /usr/local/sbin/resolvconf
        fi
    else
        case "$1" in
            apt-get)      DEBIAN_FRONTEND=noninteractive apt-get install -y openresolv ;;
            dnf)          dnf install -y openresolv || dnf install -y systemd-resolved ;;
            yum)          yum install -y openresolv ;;
            zypper)       zypper --non-interactive install openresolv ;;
            pacman)       pacman -S --noconfirm --needed openresolv ;;
            apk)          apk add --no-cache openresolv ;;
            xbps-install) xbps-install -y openresolv ;;
            emerge)       emerge --ask=n net-dns/openresolv ;;
        esac
    fi

    if command -v resolvconf >/dev/null 2>&1; then
        msg_ok "resolvconf disponivel."
    else
        msg_warn "Nao foi possivel disponibilizar resolvconf. Use tuneis sem DNS ou instale manualmente."
    fi
}

install_wg() {
    _pm=$(detect_pm) || {
        msg_err "Gerenciador de pacotes nao suportado. Instale wireguard-tools e iproute2 manualmente."
        return 1
    }
    msg_info "Gerenciador detectado: $_pm"

    case "$_pm" in
        apt-get)
            DEBIAN_FRONTEND=noninteractive apt-get update &&
            DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard-tools iproute2 ;;
        dnf)
            dnf install -y wireguard-tools iproute ||
            { dnf install -y epel-release && dnf install -y wireguard-tools iproute; } ;;
        yum)
            yum install -y epel-release && yum install -y wireguard-tools iproute ;;
        zypper)
            zypper --non-interactive install wireguard-tools iproute2 ;;
        pacman)
            pacman -S --noconfirm --needed wireguard-tools iproute2 ||
            { msg_warn "Falhou. Rode 'pacman -Syu' e tente novamente."; false; } ;;
        apk)
            apk add --no-cache wireguard-tools iproute2 ;;
        xbps-install)
            xbps-install -Sy wireguard-tools iproute2 ;;
        emerge)
            emerge --ask=n net-vpn/wireguard-tools sys-apps/iproute2 ;;
    esac || { msg_err "Falha na instalacao do WireGuard."; return 1; }

    install_resolvconf "$_pm"

    mkdir -p "$WG_DIR" && chmod 700 "$WG_DIR"

    if kernel_support; then
        msg_ok "Modulo WireGuard carregado/disponivel."
    else
        msg_warn "Kernel sem modulo WireGuard. Instale wireguard-dkms (kernel < 5.6) ou wireguard-go."
    fi

    if wg_installed; then
        msg_ok "WireGuard instalado: $(wg --version 2>/dev/null | head -n1)"
    else
        msg_err "wg/wg-quick continuam ausentes apos a instalacao."
        return 1
    fi
}

# ----------------------------------------------------------------------------
# Chave publica do cliente + bloco de cadastro no servidor
# ----------------------------------------------------------------------------
# Converte "10.8.0.2/24" em "10.8.0.2/32" (ou /128 no IPv6): no servidor o
# AllowedIPs do peer deve ser apenas o host do cliente.
host_prefix() {
    _h=${1%/*}
    if valid_ipv4 "$_h"; then printf '%s/32' "$_h"; else printf '%s/128' "$_h"; fi
}

show_peer_info() {
    _d="$WG_DIR/$1"
    _pub=$(tr -d ' \t\r\n' < "$_d/publickey" 2>/dev/null) || { msg_err "publickey de '$1' nao encontrada."; return 1; }
    if ! valid_wgkey "$_pub"; then
        msg_err "publickey de '$1' com formato invalido. Recrie o cliente."
        return 1
    fi
    if command -v wg >/dev/null 2>&1 && [ "$(wg pubkey < "$_d/privatekey")" != "$_pub" ]; then
        msg_err "publickey nao corresponde a privatekey de '$1'. Recrie o cliente."
        return 1
    fi
    _addrs=$(grep -E '^Address[[:space:]]*=' "$_d/$1.conf" | head -n1 | sed 's/^[^=]*=[[:space:]]*//' | tr -d ' ')
    _srv_allowed=""
    _ifsp=$IFS; IFS=,
    for _a in $_addrs; do
        _srv_allowed="${_srv_allowed:+$_srv_allowed,}$(host_prefix "$_a")"
    done
    IFS=$_ifsp

    printf '\n--- Cadastre este peer no SERVIDOR (tunel %s) ---\n' "$1"
    # Sem codigo de cor na chave: copia do terminal sai limpa.
    printf 'Chave publica do cliente (44 caracteres):\n%s\n' "$_pub"
    printf 'Arquivo                 : %s/publickey\n\n' "$_d"

    printf '# wg-quick (Linux) - adicionar no .conf do servidor:\n'
    printf '[Peer]\n# %s\nPublicKey = %s\n' "$1" "$_pub"
    [ -f "$_d/presharedkey" ] && printf 'PresharedKey = <mesma PSK gerada no servidor para este peer>\n'
    printf 'AllowedIPs = %s\n\n' "$(printf '%s' "$_srv_allowed" | sed 's/,/, /g')"

    printf '# MikroTik RouterOS v7:\n'
    printf '/interface wireguard peers add interface=<wg-servidor> name="%s" public-key="%s" allowed-address=%s' "$1" "$_pub" "$_srv_allowed"
    [ -f "$_d/presharedkey" ] && printf ' preshared-key="<PSK gerada no servidor>"'
    printf ' comment="%s"\n' "$1"
    printf '\n# Conferir no servidor ANTES de testar no cliente:\n'
    printf '/interface wireguard peers print detail where public-key="%s"\n' "$_pub"
    printf '# allowed-address deve conter apenas o(s) /32 do cliente (nunca as LANs do proprio servidor).\n'
}

# ----------------------------------------------------------------------------
# Utilitarios de configuracao (sem expor segredo em argumento de processo)
# ----------------------------------------------------------------------------
# rewrite_conf ARQ NOVA_PRIV MODO_PSK PSK
#   NOVA_PRIV vazio = mantem; MODO_PSK: keep | set | del
rewrite_conf() {
    _rf=$1; _rtmp="$1.tmp"
    while IFS= read -r _l || [ -n "$_l" ]; do
        case "$_l" in
            PrivateKey*=*)
                if [ -n "$2" ]; then printf 'PrivateKey = %s\n' "$2"; else printf '%s\n' "$_l"; fi ;;
            PresharedKey*=*)
                if [ "$3" = "keep" ]; then printf '%s\n' "$_l"; fi ;;
            PublicKey*=*)
                printf '%s\n' "$_l"
                if [ "$3" = "set" ]; then printf 'PresharedKey = %s\n' "$4"; fi ;;
            *)  printf '%s\n' "$_l" ;;
        esac
    done < "$_rf" > "$_rtmp" && mv "$_rtmp" "$_rf" && chmod 600 "$_rf"
}

# IP do servidor dentro do tunel, gravado como comentario no .conf
server_tunnel_ip() {
    grep -E '^# ServerTunnelIP[[:space:]]*=' "$WG_DIR/$1/$1.conf" 2>/dev/null |
        head -n1 | sed 's/^[^=]*=[[:space:]]*//'
}

# Rotas locais que se sobrepoem a cada CIDR (exceto default)
route_conflicts() {
    printf '%s\n' "$1" | tr -d ' ' | tr ',' '\n' | while IFS= read -r _c; do
        [ -n "$_c" ] || continue
        case "$_c" in 0.0.0.0/0|::/0) continue ;; esac
        case "$_c" in *:*) _fam=-6 ;; *) _fam=-4 ;; esac
        { ip "$_fam" route show to match "$_c" 2>/dev/null
          ip "$_fam" route show to root  "$_c" 2>/dev/null; } |
            grep -v '^default' | sort -u | sed "s|^|  $_c  x  |"
    done
}

# IP responde localmente (fora da VPN)? Foi a causa de um falso positivo em campo.
probe_local_ip() {
    command -v ping >/dev/null 2>&1 || return 1
    ping -c1 -W1 "$1" >/dev/null 2>&1
}

# ----------------------------------------------------------------------------
# Diagnostico de handshake
# ----------------------------------------------------------------------------
# Evidencia de campo: quando o servidor descarta a iniciacao (chave publica
# desconhecida) OU quando o cliente descarta a resposta (PSK divergente), o
# contador "received" do cliente fica em 0 nos dois casos. Quem diferencia e o
# contador do peer no SERVIDOR.
diagnose_tunnel() {
    _t=$1
    if ! tunnel_is_up "$_t"; then
        msg_err "Tunel $_t inativo. Ative antes de diagnosticar."
        return 1
    fi
    _sip=$(server_tunnel_ip "$_t")
    [ -n "$_sip" ] && ping -c1 -W1 "$_sip" >/dev/null 2>&1 &

    printf 'Aguardando handshake (ate 15s)'
    _i=0; _hs=0
    while [ "$_i" -lt 15 ]; do
        _hs=$(wg show "$_t" latest-handshakes 2>/dev/null | awk 'NR==1{print $2}')
        [ "${_hs:-0}" -gt 0 ] && break
        printf '.'; sleep 1; _i=$((_i + 1))
    done
    printf '\n'
    wait 2>/dev/null

    _rx=$(wg show "$_t" transfer 2>/dev/null | awk 'NR==1{print $2}')
    _tx=$(wg show "$_t" transfer 2>/dev/null | awk 'NR==1{print $3}')
    _pub=$(tr -d ' \t\r\n' < "$WG_DIR/$_t/publickey")
    _now=$(date +%s)

    if [ "${_hs:-0}" -gt 0 ]; then
        _age=$((_now - _hs))
        if [ "$_age" -le 180 ]; then
            msg_ok "Handshake OK ha ${_age}s | recebido ${_rx:-0} B, enviado ${_tx:-0} B."
            if [ -n "$_sip" ]; then
                if ping -c2 -W2 "$_sip" >/dev/null 2>&1; then
                    msg_ok "Servidor no tunel ($_sip) responde."
                else
                    msg_warn "Handshake OK, mas $_sip nao responde: verificar firewall input/ICMP no servidor."
                fi
            fi
            return 0
        fi
        msg_warn "Ultimo handshake ha ${_age}s (> 180s): sessao expirada ou sem trafego."
    else
        msg_err "Sem handshake. Enviado ${_tx:-0} B, recebido ${_rx:-0} B."
    fi

    printf '\nConfira no SERVIDOR (MikroTik) e compare os contadores rx/tx do peer:\n'
    printf '  /interface wireguard print detail\n'
    printf '  /interface wireguard peers print detail where public-key="%s"\n\n' "$_pub"
    printf 'Leitura:\n'
    printf '  - Nenhum peer encontrado ou rx/tx parados: servidor nao reconhece a chave publica\n'
    printf '    do cliente (peer com chave antiga ou colada errada) ou UDP bloqueado no caminho.\n'
    printf '  - rx e tx do peer crescendo, sem handshake: PSK divergente entre as pontas.\n'
    printf '  - public-key da interface do servidor diferente de "PublicKey" do [Peer] no cliente:\n'
    printf '    chave do servidor errada no cliente.\n'
    printf '  - Depois de todo "set" no servidor, rode o print detail antes de testar de novo.\n'
    return 1
}

# ----------------------------------------------------------------------------
# Rotacao de chaves, PSK e exibicao segura
# ----------------------------------------------------------------------------
rotate_keys() {
    select_tunnel _rt || return 1
    _d="$WG_DIR/$_rt"
    msg_warn "O tunel para de funcionar ate o servidor receber a nova chave publica."
    confirm "Rotacionar o par de chaves de '$_rt'?" || { msg_info "Cancelado."; return 0; }

    _old=$(tr -d ' \t\r\n' < "$_d/publickey")
    _bk=$(backup_tunnel "$_rt" antes-rotacao) || { msg_err "Falha no backup. Rotacao abortada."; return 1; }
    msg_info "Backup: $_bk (reverter: menu 16)"
    _was_up=0
    if tunnel_is_up "$_rt"; then _was_up=1; wg-quick down "$_rt"; fi

    if ! { wg genkey > "$_d/privatekey.new" && wg pubkey < "$_d/privatekey.new" > "$_d/publickey.new"; }; then
        rm -f "$_d/privatekey.new" "$_d/publickey.new"
        msg_err "Falha ao gerar novo par. Chaves atuais mantidas."
        return 1
    fi
    mv "$_d/privatekey.new" "$_d/privatekey"
    mv "$_d/publickey.new" "$_d/publickey"
    rewrite_conf "$_d/$_rt.conf" "$(cat "$_d/privatekey")" keep ""
    chmod 600 "$_d"/*
    _new=$(tr -d ' \t\r\n' < "$_d/publickey")
    msg_ok "Novo par gerado para '$_rt'."

    printf '\n--- Atualize o peer no SERVIDOR ---\n'
    printf 'Nova chave publica do cliente:\n%s\n\n' "$_new"
    printf '# MikroTik RouterOS v7 (localiza o peer pela chave antiga):\n'
    printf '/interface wireguard peers set [find public-key="%s"] public-key="%s"\n' "$_old" "$_new"
    printf '/interface wireguard peers print detail where public-key="%s"\n\n' "$_new"
    printf '# wg-quick (Linux): troque "PublicKey = %s" por "PublicKey = %s"\n' "$_old" "$_new"

    if [ "$_was_up" -eq 1 ] || confirm "Subir o tunel agora?"; then
        printf '\n'
        if confirm "Servidor ja atualizado com a nova chave publica?"; then
            tunnel_up "$_rt"
        else
            msg_info "Suba depois pela opcao 6 do menu."
        fi
    fi
}

update_psk() {
    select_tunnel _up || return 1
    _d="$WG_DIR/$_up"
    while :; do
        ask_secret _psk "Nova PSK gerada no servidor (Enter = remover PSK)"
        [ -z "$_psk" ] && break
        valid_wgkey "$_psk" && break
        msg_err "PSK invalida (44 caracteres base64 terminando em '=')."
    done

    _bk=$(backup_tunnel "$_up" antes-psk) || { msg_err "Falha no backup. Operacao abortada."; return 1; }
    msg_info "Backup: $_bk (reverter: menu 16)"
    if [ -n "$_psk" ]; then
        rewrite_conf "$_d/$_up.conf" "" set "$_psk"
        printf '%s\n' "$_psk" > "$_d/presharedkey"
        chmod 600 "$_d/presharedkey"
        msg_ok "PSK atualizada em '$_up'."
    else
        rewrite_conf "$_d/$_up.conf" "" del ""
        rm -f "$_d/presharedkey"
        msg_ok "PSK removida de '$_up'. Remova tambem no servidor (preshared-key=\"\")."
    fi
    _psk=""

    if tunnel_is_up "$_up"; then
        wg-quick down "$_up" && tunnel_up "$_up"
    fi
}

show_conf_masked() {
    select_tunnel _sc || return 1
    printf '\n'
    sed -E 's/^(PrivateKey|PresharedKey)[[:space:]]*=.*/\1 = <oculta>/' "$WG_DIR/$_sc/$_sc.conf"
    printf '\n'
    msg_info "Saida segura para enviar a suporte/chamado."
}

# render_conf ARQ_PRIVKEY -> .conf a partir das variaveis globais do fluxo
render_conf() {
    printf '# Tunel WireGuard: %s\n' "$TUN"
    printf '# Gerado por wg-client-manager.sh v%s em %s\n' "$VERSION" "$(date '+%Y-%m-%d %H:%M:%S')"
    if [ -n "$SRV_TIP" ]; then printf '# ServerTunnelIP = %s\n' "$SRV_TIP"; fi
    printf '\n[Interface]\n'
    printf 'PrivateKey = %s\n' "$(cat "$1")"
    printf 'Address = %s\n' "$ADDR"
    if [ -n "$MTU" ]; then printf 'MTU = %s\n' "$MTU"; fi
    if [ -n "$DNS" ]; then printf 'DNS = %s\n' "$DNS"; fi
    printf '\n[Peer]\n'
    printf 'PublicKey = %s\n' "$SRV_PUB"
    if [ -n "$PSK" ]; then printf 'PresharedKey = %s\n' "$PSK"; fi
    printf 'Endpoint = %s:%s\n' "$SRV_FMT" "$SRV_PORT"
    printf 'AllowedIPs = %s\n' "$ALLOWED"
    if [ "$KA" -gt 0 ]; then printf 'PersistentKeepalive = %s\n' "$KA"; fi
}

valid_mtu() {
    case "$1" in ''|*[!0-9]*|0*) return 1 ;; esac
    [ "$1" -ge 1280 ] && [ "$1" -le 9000 ]
}

# ----------------------------------------------------------------------------
# Criacao do cliente
# ----------------------------------------------------------------------------
create_client() {
    if ! wg_installed; then
        msg_err "WireGuard nao instalado. Use a opcao 2 do menu."
        return 1
    fi
    mkdir -p "$WG_DIR" && chmod 700 "$WG_DIR"

    printf '\n--- Novo cliente WireGuard ---\n'

    # 1. Nome do tunel
    while :; do
        ask TUN "Nome do tunel (a-z 0-9 - _, inicia com letra, max 15)"
        if ! valid_tunnel_name "$TUN"; then
            msg_err "Nome invalido. Ex.: wg-matriz, vpn_sp01. Sem maiusculas, espacos ou acentos."
            continue
        fi
        if [ -e "$WG_DIR/$TUN" ] || [ -e "$WG_DIR/$TUN.conf" ]; then
            msg_err "Ja existe configuracao para '$TUN' em $WG_DIR."
            continue
        fi
        if ip link show "$TUN" >/dev/null 2>&1; then
            msg_err "Ja existe uma interface de rede chamada '$TUN'."
            continue
        fi
        break
    done

    # 2. Endpoint do servidor
    while :; do
        ask SRV_HOST "IP ou hostname do servidor WireGuard"
        if valid_ipv4 "$SRV_HOST"; then
            SRV_FMT=$SRV_HOST; break
        elif valid_fqdn "$SRV_HOST"; then
            if command -v getent >/dev/null 2>&1 && ! getent hosts "$SRV_HOST" >/dev/null 2>&1; then
                msg_warn "$SRV_HOST nao resolve neste momento. Confira o DNS/DDNS do servidor."
            fi
            SRV_FMT=$SRV_HOST; break
        elif valid_ipv6 "$SRV_HOST"; then
            SRV_FMT="[$SRV_HOST]"; break
        fi
        msg_err "Endereco invalido. Informe IPv4, IPv6 ou FQDN (ex.: vpn.empresa.com.br)."
    done

    # 3. Porta
    while :; do
        ask SRV_PORT "Porta do servidor" "51820"
        valid_port "$SRV_PORT" && break
        msg_err "Porta invalida (1-65535)."
    done

    # 4. Chave publica do servidor (obrigatoria para o [Peer])
    while :; do
        ask SRV_PUB "Chave publica do servidor"
        valid_wgkey "$SRV_PUB" && break
        msg_err "Chave invalida. Deve ter 44 caracteres base64 terminando em '='."
    done

    # 5. Endereco do cliente dentro do tunel
    while :; do
        ask ADDR_IN "Endereco do cliente no tunel (CIDR, ex.: 10.8.0.2/32)"
        ADDR=$(normalize_list "$ADDR_IN" valid_cidr) && break
        msg_err "CIDR invalido. Varios separados por virgula: 10.8.0.2/32, fd00::2/128"
    done

    # 6. Allowed address
    while :; do
        ask ALLOWED_IN "Allowed address (CIDR, ex.: 10.8.0.0/24, 192.168.10.0/24)"
        ALLOWED=$(normalize_list "$ALLOWED_IN" valid_cidr) && break
        msg_err "Lista invalida. Use CIDR separado por virgula."
    done
    case "$ALLOWED" in
        *0.0.0.0/0*|*::/0*) msg_warn "Full tunnel: todo o trafego do host saira pela VPN. Garanta que o endpoint nao dependa da propria VPN." ;;
    esac

    # 6b. IP do servidor dentro do tunel: vira /32 no AllowedIPs para permitir
    #     gerencia e teste de ping do proprio servidor pela VPN.
    SRV_TIP=""
    while :; do
        ask SRV_TIP "IP do servidor dentro do tunel (opcional, ex.: 172.16.0.1 | Enter = pular)"
        [ -z "$SRV_TIP" ] && break
        valid_ip "$SRV_TIP" && break
        msg_err "IP invalido."
        SRV_TIP=""
    done
    if [ -n "$SRV_TIP" ]; then
        ALLOWED=$(normalize_list "$ALLOWED, $(host_prefix "$SRV_TIP")" valid_cidr)
        if probe_local_ip "$SRV_TIP"; then
            msg_warn "$SRV_TIP JA responde na rede local (fora da VPN): $(ip route get "$SRV_TIP" 2>/dev/null | head -n1)"
            msg_warn "Sobreposicao: com o tunel ativo, a rota /32 pela VPN esconde esse IP local."
            msg_warn "Recomendado: sub-rede de tunel exclusiva no servidor."
            confirm "Continuar mesmo assim?" || { msg_info "Operacao cancelada."; return 0; }
        fi
    fi

    # 6c. Sobreposicao do AllowedIPs com rotas locais existentes
    _conflicts=$(route_conflicts "$ALLOWED")
    if [ -n "$_conflicts" ]; then
        msg_warn "AllowedIPs sobrepoe rotas ja existentes neste host (rede x rota):"
        printf '%s\n' "$_conflicts"
        msg_warn "Com o tunel ativo o trafego dessas faixas pode ir para o lugar errado."
        confirm "Continuar mesmo assim?" || { msg_info "Operacao cancelada."; return 0; }
    fi

    # 7. Preshared key (opcional)
    # A PSK e gerada no servidor (wg genpsk / RouterOS) e colada aqui.
    PSK=""
    while :; do
        ask_secret PSK "Preshared key gerada no servidor (Enter = sem PSK)"
        [ -z "$PSK" ] && break
        valid_wgkey "$PSK" && break
        msg_err "PSK invalida (44 caracteres base64 terminando em '=')."
        PSK=""
    done

    # 8. DNS (opcional)
    DNS=""
    while :; do
        ask DNS_IN "DNS (opcional, ex.: 10.8.0.1, 1.1.1.1 | Enter = sem DNS)"
        [ -z "$DNS_IN" ] && break
        DNS=$(normalize_list "$DNS_IN" valid_ip) && break
        msg_err "DNS invalido. Informe apenas IPs separados por virgula."
        DNS=""
    done
    if [ -n "$DNS" ] && ! command -v resolvconf >/dev/null 2>&1; then
        msg_warn "resolvconf ausente: wg-quick vai falhar ao aplicar DNS. Use a opcao 2 para instalar."
    fi

    # 9. Persistent keepalive
    while :; do
        ask KA "Persistent keepalive em segundos (0 = desativado)" "25"
        valid_keepalive "$KA" && break
        msg_err "Valor invalido (0-65535)."
    done

    # 10. MTU (opcional)
    MTU=""
    while :; do
        ask MTU "MTU do tunel (Enter = automatico do wg-quick | teste pelo menu 14 > 3)"
        [ -z "$MTU" ] && break
        valid_mtu "$MTU" && break
        msg_err "MTU invalido (1280-9000)."
        MTU=""
    done

    # Resumo
    printf '\n--- Resumo ---\n'
    printf 'Tunel ............: %s\n' "$TUN"
    printf 'Endpoint .........: %s:%s\n' "$SRV_FMT" "$SRV_PORT"
    printf 'Pubkey servidor ..: %s\n' "$SRV_PUB"
    printf 'Address ..........: %s\n' "$ADDR"
    printf 'AllowedIPs .......: %s\n' "$ALLOWED"
    printf 'Servidor no tunel : %s\n' "${SRV_TIP:-nao informado}"
    if [ -n "$PSK" ]; then printf 'PresharedKey .....: [definida]\n'; else printf 'PresharedKey .....: nao\n'; fi
    printf 'DNS ..............: %s\n' "${DNS:-nao}"
    printf 'Keepalive ........: %s\n' "$KA"
    printf 'MTU ..............: %s\n' "${MTU:-automatico}"
    printf 'Pasta ............: %s/%s\n\n' "$WG_DIR" "$TUN"

    if ! confirm "Gravar configuracao?"; then
        msg_info "Operacao cancelada. Nada foi gravado."
        return 0
    fi

    # Gravacao
    _dir="$WG_DIR/$TUN"
    _conf="$_dir/$TUN.conf"
    mkdir -m 700 "$_dir" || { msg_err "Falha ao criar $_dir"; return 1; }

    if ! { wg genkey > "$_dir/privatekey" && wg pubkey < "$_dir/privatekey" > "$_dir/publickey"; }; then
        msg_err "Falha ao gerar chaves. Revertendo."
        rm -rf "$_dir"
        return 1
    fi

    if [ -n "$PSK" ]; then
        printf '%s\n' "$PSK" > "$_dir/presharedkey"
    fi

    render_conf "$_dir/privatekey" > "$_conf"

    chmod 600 "$_dir"/*
    ln -s "$TUN/$TUN.conf" "$WG_DIR/$TUN.conf"
    PSK=""

    msg_ok "Configuracao gravada em $_conf"
    show_peer_info "$TUN"


    printf '\n'
    if confirm "Ativar o tunel agora?"; then
        tunnel_up "$TUN"
    fi
}

# ----------------------------------------------------------------------------
# Gestao de tuneis
# ----------------------------------------------------------------------------
list_clients() {
    printf '\n%-16s %-6s %s\n' "TUNEL" "ESTADO" "ENDPOINT"
    _found=0
    for _d in "$WG_DIR"/*/; do
        [ -d "$_d" ] || continue
        _n=$(basename "$_d")
        tunnel_exists "$_n" || continue
        _found=1
        _ep=$(grep -E '^Endpoint[[:space:]]*=' "$WG_DIR/$_n/$_n.conf" | head -n1 | sed 's/^[^=]*=[[:space:]]*//')
        _pk=$(cat "$WG_DIR/$_n/publickey" 2>/dev/null || printf '-')
        if tunnel_is_up "$_n"; then _st="UP"; else _st="DOWN"; fi
        printf '%-16s %-6s %s\n' "$_n" "$_st" "$_ep"
        printf '  pubkey: %s\n' "$_pk"
    done
    [ "$_found" -eq 1 ] || msg_info "Nenhum cliente criado por este script em $WG_DIR."
}

# select_tunnel VAR -> pede nome e valida existencia
select_tunnel() {
    list_clients
    printf '\n'
    ask _sel "Nome do tunel"
    if ! valid_tunnel_name "$_sel" || ! tunnel_exists "$_sel"; then
        msg_err "Tunel '$_sel' nao encontrado."
        return 1
    fi
    eval "$1=\$_sel"
}

tunnel_up() {
    if tunnel_is_up "$1"; then
        msg_info "Tunel $1 ja esta ativo."
        return 0
    fi
    rm -f "$WG_DIR/$1/.admin-down"
    if wg-quick up "$1"; then
        msg_ok "Interface $1 ativa."
        diagnose_tunnel "$1"
    else
        msg_err "Falha ao subir $1. Verifique chave do servidor, endpoint, porta e firewall."
        return 1
    fi
}

tunnel_down() {
    if ! tunnel_is_up "$1"; then
        : > "$WG_DIR/$1/.admin-down"
        msg_info "Tunel $1 ja esta inativo."
        return 0
    fi
    # Marca desligamento administrativo: o watchdog nao religa o tunel.
    : > "$WG_DIR/$1/.admin-down"
    wg-quick down "$1" && msg_ok "Tunel $1 desativado (watchdog nao religa ate ativar de novo)."
}

tunnel_boot() {
    case "$(init_system)" in
        systemd)
            systemctl enable "wg-quick@$1" && msg_ok "wg-quick@$1 habilitado no boot." ;;
        openrc)
            if [ -x /etc/init.d/wg-quick ]; then
                ln -sf wg-quick "/etc/init.d/wg-quick.$1" &&
                rc-update add "wg-quick.$1" default && msg_ok "wg-quick.$1 habilitado no boot."
            else
                msg_err "Script /etc/init.d/wg-quick ausente. Instale wireguard-tools-openrc (Alpine)."
                return 1
            fi ;;
        *)
            msg_warn "Init nao identificado. Adicione 'wg-quick up $1' na inicializacao manualmente."
            return 1 ;;
    esac
}

tunnel_noboot() {
    case "$(init_system)" in
        systemd) systemctl disable "wg-quick@$1" >/dev/null 2>&1 || true ;;
        openrc)
            rc-update del "wg-quick.$1" default >/dev/null 2>&1 || true
            rm -f "/etc/init.d/wg-quick.$1" ;;
    esac
}

show_status() {
    if ! wg_installed; then
        msg_err "WireGuard nao instalado."
        return 1
    fi
    # "wg show" nunca exibe private key; mascaramos o resto por garantia.
    wg show all 2>/dev/null | sed -e '/private key/d' -e '/preshared key/d'
    [ -n "$(wg show interfaces 2>/dev/null)" ] || msg_info "Nenhum tunel ativo."
}

remove_client() {
    select_tunnel _rm || return 1
    msg_warn "Isso apaga chaves e configuracao de '$_rm' definitivamente."
    ask _chk "Digite o nome do tunel para confirmar"
    if [ "$_chk" != "$_rm" ]; then
        msg_info "Confirmacao nao confere. Nada foi removido."
        return 0
    fi
    tunnel_is_up "$_rm" && wg-quick down "$_rm"
    tunnel_noboot "$_rm"
    rm -f "$WG_DIR/$_rm.conf"
    rm -rf "${WG_DIR:?}/$_rm"
    msg_ok "Cliente '$_rm' removido. Remova tambem o peer correspondente no servidor."
}

# ----------------------------------------------------------------------------
# Debug / troubleshooting
# ----------------------------------------------------------------------------
# O modulo WireGuard do kernel so registra eventos de handshake, keepalive e
# pacotes rejeitados quando o dynamic debug esta ativo. Sem ele o WireGuard e
# silencioso por design. Requer CONFIG_DYNAMIC_DEBUG e debugfs acessivel
# (Secure Boot com kernel lockdown bloqueia a escrita no debugfs).

lockdown_state() {
    [ -r /sys/kernel/security/lockdown ] || { printf 'n/d'; return; }
    sed -n 's/.*\[\(.*\)\].*/\1/p' /sys/kernel/security/lockdown
}

debug_on() {
    [ -d /sys/module/wireguard ] || modprobe wireguard >/dev/null 2>&1
    if [ ! -e "$DYN_CTRL" ]; then
        mount -t debugfs none /sys/kernel/debug >/dev/null 2>&1
    fi
    if [ ! -e "$DYN_CTRL" ]; then
        msg_warn "Dynamic debug indisponivel (kernel sem CONFIG_DYNAMIC_DEBUG ou debugfs ausente)."
        return 1
    fi
    if echo 'module wireguard +p' > "$DYN_CTRL" 2>/dev/null; then
        DEBUG_ACTIVE=1
        return 0
    fi
    msg_warn "Escrita no dynamic debug negada. Kernel lockdown: $(lockdown_state)."
    msg_warn "Com Secure Boot ativo o log do kernel fica indisponivel; a captura UDP continua valida."
    return 1
}

debug_status() {
    printf '\n--- Status do debug ---\n'
    print_log_destinations
    msg_info "Kernel lockdown: $(lockdown_state)"
    if [ ! -e "$DYN_CTRL" ]; then
        msg_info "Dynamic debug: nao montado/disponivel."
    else
        _n=$(grep -c 'wireguard.*=p' "$DYN_CTRL" 2>/dev/null)
        if [ "${_n:-0}" -gt 0 ]; then
            msg_warn "Debug WireGuard ATIVO no kernel ($_n pontos). Desative ao terminar."
        else
            msg_ok "Debug WireGuard desativado."
        fi
    fi
    if command -v tcpdump >/dev/null 2>&1; then msg_ok "tcpdump disponivel."
    else msg_info "tcpdump ausente (instalado sob demanda na captura guiada)."; fi
    _nlog=$(find "$LOG_DIR" -type f -name '*.log' 2>/dev/null | wc -l)
    msg_info "Relatorios em $LOG_DIR: ${_nlog:-0}"
}

debug_force_off() {
    [ -e "$DYN_CTRL" ] && echo 'module wireguard -p' > "$DYN_CTRL" 2>/dev/null
    DEBUG_ACTIVE=0
    msg_ok "Debug WireGuard desativado no kernel."
}

ensure_tcpdump() {
    command -v tcpdump >/dev/null 2>&1 && return 0
    confirm "tcpdump nao instalado. Instalar agora (recomendado para a captura)?" || return 1
    _pm=$(detect_pm) || { msg_err "Gerenciador de pacotes nao suportado."; return 1; }
    case "$_pm" in
        apt-get)      DEBIAN_FRONTEND=noninteractive apt-get install -y tcpdump ;;
        dnf|yum)      "$_pm" install -y tcpdump ;;
        zypper)       zypper --non-interactive install tcpdump ;;
        pacman)       pacman -S --noconfirm --needed tcpdump ;;
        apk)          apk add --no-cache tcpdump ;;
        xbps-install) xbps-install -y tcpdump ;;
        emerge)       emerge --ask=n net-analyzer/tcpdump ;;
    esac >/dev/null 2>&1
    command -v tcpdump >/dev/null 2>&1
}

# Leitura do log do kernel desde um instante (journalctl) ou por diferenca de linhas (dmesg)
kernel_log_since() {
    if command -v journalctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        journalctl -k --since "@$1" --no-pager -o short-precise 2>/dev/null | grep -i 'wireguard'
    else
        dmesg 2>/dev/null | tail -n +"$(( $2 + 1 ))" | grep -i 'wireguard'
    fi
}

mask_secrets() {
    sed -E -e 's/^(PrivateKey|PresharedKey)[[:space:]]*=.*/\1 = <oculta>/' \
           -e 's/(private key|preshared key):.*/\1: (oculta)/'
}

# analyze_capture KLOG UDPLOG EP_IP EP_PORT HANDSHAKE_OK PING_OK PING_TOTAL SIP
analyze_capture() {
    _k=$1; _u=$2; _eip=$3; _ep=$4; _hsok=$5; _pok=$6; _ptot=$7; _sip=$8
    _init=$(grep -c 'Sending handshake initiation' "$_k" 2>/dev/null)
    _resp=$(grep -c 'Receiving handshake response' "$_k" 2>/dev/null)
    _inv=$(grep -c 'Invalid handshake' "$_k" 2>/dev/null)
    _kp=$(grep -c 'Keypair .* created' "$_k" 2>/dev/null)
    _unal=$(grep -c 'unallowed src IP' "$_k" 2>/dev/null)
    _noep=$(grep -c 'No valid endpoint' "$_k" 2>/dev/null)
    _klines=$(wc -l < "$_k" 2>/dev/null)
    _out=0; _in=0; _in92=0; _out148=0
    if [ -s "$_u" ]; then
        _out=$(grep -cF "> $_eip.$_ep:" "$_u")
        _in=$(grep -cF "$_eip.$_ep >" "$_u")
        _out148=$(grep -F "> $_eip.$_ep:" "$_u" | grep -c 'length 148')
        _in92=$(grep -F "$_eip.$_ep >" "$_u" | grep -c 'length 92')
    fi

    printf 'Kernel : iniciacoes=%s respostas=%s invalidos=%s keypairs=%s unallowed_src=%s sem_endpoint=%s (linhas=%s)\n' \
        "${_init:-0}" "${_resp:-0}" "${_inv:-0}" "${_kp:-0}" "${_unal:-0}" "${_noep:-0}" "${_klines:-0}"
    printf 'UDP    : saindo=%s (iniciacao 148B=%s) | chegando=%s (resposta 92B=%s)\n' \
        "$_out" "$_out148" "$_in" "$_in92"
    [ -n "$_sip" ] && printf 'Ping   : %s/%s respostas de %s\n' "$_pok" "$_ptot" "$_sip"
    printf '\n'

    _found=0
    if [ "$_hsok" -eq 1 ] || [ "${_kp:-0}" -gt 0 ]; then
        printf '[OK] Handshake estabelecido.\n'; _found=1
        if [ -n "$_sip" ] && [ "$_pok" -eq 0 ]; then
            printf '[CAUSA] Tunel OK, mas %s nao responde: firewall input/ICMP no servidor\n' "$_sip"
            printf '        ou IP do servidor no tunel diferente de %s.\n' "$_sip"
        fi
    else
        if [ "${_inv:-0}" -gt 0 ] || [ "$_in92" -gt 0 ]; then
            printf '[CAUSA] O servidor RESPONDE, mas a resposta e rejeitada pelo cliente.\n'
            printf '        Provavel: PSK divergente entre as pontas, ou PublicKey do servidor\n'
            printf '        errada no [Peer] do cliente.\n'; _found=1
        elif [ "$_out" -gt 0 ] || [ "${_init:-0}" -gt 0 ]; then
            if [ "$_in" -eq 0 ]; then
                printf '[CAUSA] Iniciacoes saem e NENHUM pacote volta do servidor.\n'
                printf '        Provavel: chave publica do cliente ausente/errada no peer do servidor,\n'
                printf '        UDP %s bloqueado no caminho, ou endpoint/porta incorretos.\n' "$_ep"; _found=1
            fi
        fi
        if [ "${_noep:-0}" -gt 0 ]; then
            printf '[CAUSA] Peer sem endpoint valido: verifique Endpoint e resolucao DNS/DDNS.\n'; _found=1
        fi
    fi
    if [ "${_unal:-0}" -gt 0 ]; then
        printf '[CAUSA] Pacotes com IP de origem fora do AllowedIPs do cliente foram descartados.\n'
        printf '        Inclua a rede de origem no AllowedIPs ou revise NAT/masquerade no servidor.\n'; _found=1
    fi
    if [ "$_found" -eq 0 ]; then
        printf '[INFO] Sem evidencia conclusiva. Aumente a duracao da captura ou habilite\n'
        printf '       o log do lado do servidor (comandos abaixo).\n'
    fi
    if [ "${_klines:-0}" -eq 0 ] && [ ! -s "$_u" ]; then
        printf '[AVISO] Sem log do kernel e sem captura UDP: analise limitada.\n'
    fi
}

debug_capture() {
    select_tunnel _dt || return 1
    while :; do
        ask _dur "Duracao da captura em segundos (10-600)" "30"
        case "$_dur" in ''|*[!0-9]*) ;; *) [ "$_dur" -ge 10 ] && [ "$_dur" -le 600 ] && break ;; esac
        msg_err "Informe um valor entre 10 e 600."
    done
    _restart=0
    confirm "Reiniciar o tunel no inicio (registra o handshake desde o zero)?" && _restart=1

    mkdir -p "$LOG_DIR" && chmod 700 "$LOG_DIR"
    apply_retention >/dev/null
    _stamp=$(date '+%Y%m%d-%H%M%S')
    _log="$LOG_DIR/${_dt}-${_stamp}.log"
    _klog="$LOG_DIR/.${_dt}-${_stamp}.klog"
    _ulog="$LOG_DIR/.${_dt}-${_stamp}.udp"
    : > "$_log"; : > "$_klog"; : > "$_ulog"

    _kdebug=0; debug_on && _kdebug=1
    _t0=$(date +%s)
    _dm0=$(dmesg 2>/dev/null | wc -l)

    if [ "$_restart" -eq 1 ] && tunnel_is_up "$_dt"; then
        wg-quick down "$_dt" >> "$_log" 2>&1
    fi
    tunnel_is_up "$_dt" || wg-quick up "$_dt" >> "$_log" 2>&1

    _epraw=$(wg show "$_dt" endpoints 2>/dev/null | awk 'NR==1{print $2}')
    _eport=${_epraw##*:}
    _eip=${_epraw%:*}; _eip=${_eip#[}; _eip=${_eip%]}
    _sip=$(server_tunnel_ip "$_dt")

    _tpid=""
    if [ -n "$_eip" ] && [ "$_eip" != "(none)" ] && ensure_tcpdump; then
        tcpdump -l -nn -i any "udp and host $_eip and port $_eport" > "$_ulog" 2>/dev/null &
        _tpid=$!
    fi

    printf '\n'
    msg_info "Relatorio sera salvo em: $_log"
    msg_info "Eventos do kernel tambem ficam em: $(kernel_log_source)"
    msg_info "Capturando por ${_dur}s (kernel debug: $([ "$_kdebug" -eq 1 ] && echo sim || echo nao) | tcpdump: $([ -n "$_tpid" ] && echo sim || echo nao))"
    # Janela controlada por relogio: o tempo real da captura nao depende do RTT do ping.
    _pok=0; _ptot=0; _samples=""; _next=5
    _tend=$(( $(date +%s) + _dur ))
    while [ "$(date +%s)" -lt "$_tend" ]; do
        if [ -n "$_sip" ]; then
            _ptot=$((_ptot + 1))
            ping -c1 -W1 "$_sip" >/dev/null 2>&1 && _pok=$((_pok + 1))
        fi
        sleep 1
        _i=$(( $(date +%s) - _t0 ))
        if [ "$_i" -ge "$_next" ]; then
            _next=$((_next + 5))
            _hs=$(wg show "$_dt" latest-handshakes 2>/dev/null | awk 'NR==1{print $2}')
            _tr=$(wg show "$_dt" transfer 2>/dev/null | awk 'NR==1{print "rx=" $2 "B tx=" $3 "B"}')
            _samples="${_samples}t+${_i}s handshake_epoch=${_hs:-0} ${_tr}
"
            printf '.'
        fi
    done
    printf '\n'

    [ -n "$_tpid" ] && { kill "$_tpid" 2>/dev/null; wait "$_tpid" 2>/dev/null; }
    debug_off
    kernel_log_since "$_t0" "$_dm0" > "$_klog"

    _hs=$(wg show "$_dt" latest-handshakes 2>/dev/null | awk 'NR==1{print $2}')
    _hsok=0
    [ "${_hs:-0}" -ge "$_t0" ] 2>/dev/null && _hsok=1
    [ "${_hs:-0}" -gt 0 ] && [ $(( $(date +%s) - _hs )) -le 180 ] && _hsok=1

    _analysis=$(analyze_capture "$_klog" "$_ulog" "$_eip" "$_eport" "$_hsok" "$_pok" "$_ptot" "$_sip")
    _pub=$(tr -d ' \t\r\n' < "$WG_DIR/$_dt/publickey")

    {
        printf '=====================================================\n'
        printf ' Relatorio de debug WireGuard | tunel %s | %s\n' "$_dt" "$(date '+%Y-%m-%d %H:%M:%S')"
        printf ' wg-client-manager.sh v%s | duracao %ss | restart=%s\n' "$VERSION" "$_dur" "$_restart"
        printf '=====================================================\n\n'
        printf '== Analise automatica ==\n%s\n\n' "$_analysis"
        printf '== Ambiente ==\n'
        printf 'OS: %s\n' "$( (. /etc/os-release 2>/dev/null && printf '%s' "${PRETTY_NAME:-n/d}") )"
        printf 'Kernel: %s | lockdown: %s | init: %s\n' "$(uname -r)" "$(lockdown_state)" "$(init_system)"
        printf 'wg: %s\n' "$(wg --version 2>/dev/null | head -n1)"
        printf 'Kernel debug: %s | tcpdump: %s\n' "$_kdebug" "$([ -n "$_tpid" ] && echo 1 || echo 0)"
        printf 'Firewall local: %s\n\n' "$(detect_firewall)"
        printf '== Configuracao (chaves ocultas) ==\n'
        mask_secrets < "$WG_DIR/$_dt/$_dt.conf"
        printf '\n== Estado WireGuard (final) ==\n'
        wg show "$_dt" 2>&1 | mask_secrets
        printf '\n== Amostras a cada 5s ==\n%s\n' "$_samples"
        printf '== Interface e rotas ==\n'
        ip addr show dev "$_dt" 2>&1
        ip route show dev "$_dt" 2>&1
        if [ -n "$_eip" ] && [ "$_eip" != "(none)" ]; then
            printf 'Rota ate o endpoint: %s\n' "$(ip route get "$_eip" 2>&1 | head -n1)"
            _odev=$(ip route get "$_eip" 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -n1)
            [ -n "$_odev" ] && printf 'MTU %s: %s | MTU %s: %s\n' "$_odev" \
                "$(cat /sys/class/net/"$_odev"/mtu 2>/dev/null)" "$_dt" "$(cat /sys/class/net/"$_dt"/mtu 2>/dev/null)"
        fi
        printf '\n== Captura UDP (%s:%s) ==\n' "$_eip" "$_eport"
        if [ -s "$_ulog" ]; then cat "$_ulog"; else printf '(sem pacotes ou tcpdump indisponivel)\n'; fi
        printf '\n== Log do kernel (wireguard) ==\n'
        if [ -s "$_klog" ]; then cat "$_klog"; else printf '(vazio: debug indisponivel ou sem eventos)\n'; fi
        printf '\n== Lado servidor (MikroTik RouterOS v7) ==\n'
        printf '/interface wireguard peers print detail where public-key="%s"\n' "$_pub"
        printf '/system logging add topics=wireguard,debug action=memory\n'
        printf '/log print where topics~"wireguard"\n'
        printf '/system logging remove [find topics~"wireguard"]   # desligar ao terminar\n'
    } >> "$_log" 2>&1

    rm -f "$_klog" "$_ulog"
    chmod 600 "$_log"

    printf '\n--- Analise automatica ---\n%s\n\n' "$_analysis"
    msg_ok "Relatorio completo: $_log"
    msg_info "Chaves privadas e PSK ficam ocultas no relatorio. Chaves publicas e IPs aparecem."
}

kernel_log_source() {
    if command -v journalctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        printf 'journal do systemd (consulta: journalctl -k | grep -i wireguard)'
    elif dmesg --help 2>&1 | grep -q -- '--follow'; then
        printf 'ring buffer do kernel (consulta: dmesg | grep -i wireguard)'
    elif [ -r /var/log/messages ]; then
        printf '/var/log/messages (consulta: grep -i wireguard /var/log/messages)'
    else
        printf 'ring buffer do kernel (consulta: dmesg | grep -i wireguard)'
    fi
}

print_log_destinations() {
    printf 'Destino dos logs (tudo fica local, nada e enviado para fora da maquina):\n'
    printf '  Relatorios do script : %s/  (pasta 700, arquivos 600)\n' "$LOG_DIR"
    printf '  Eventos do kernel    : %s\n' "$(kernel_log_source)"
}

list_reports() {
    printf '\n--- Relatorios salvos em %s ---\n' "$LOG_DIR"
    if [ -z "$(find "$LOG_DIR" -maxdepth 1 -type f -name '*.log' 2>/dev/null | head -n1)" ]; then
        msg_info "Nenhum relatorio salvo."
        return 0
    fi
    # shellcheck disable=SC2012
    ls -lt "$LOG_DIR"/*.log 2>/dev/null | awk '{printf "  %s %s %s  %8s B  %s\n", $6, $7, $8, $5, $9}'
}

show_last_report() {
    # shellcheck disable=SC2012
    _last=$(ls -t "$LOG_DIR"/*.log 2>/dev/null | head -n1)
    if [ -z "$_last" ]; then
        msg_info "Nenhum relatorio salvo em $LOG_DIR."
        return 0
    fi
    msg_info "Exibindo: $_last"
    if command -v less >/dev/null 2>&1 && [ -t 1 ]; then less "$_last"; else cat "$_last"; fi
}

debug_live() {
    if ! debug_on; then
        msg_err "Sem debug do kernel nao ha o que acompanhar ao vivo. Use a captura guiada (tcpdump)."
        return 1
    fi
    _lf="/dev/null"
    if confirm "Gravar tambem em arquivo?"; then
        mkdir -p "$LOG_DIR" && chmod 700 "$LOG_DIR"
        _lf="$LOG_DIR/live-$(date '+%Y%m%d-%H%M%S').log"
        : > "$_lf" && chmod 600 "$_lf"
    fi
    printf '\n'
    msg_info "Fonte : $(kernel_log_source)"
    if [ "$_lf" != "/dev/null" ]; then
        msg_info "Arquivo: $_lf"
    else
        msg_info "Arquivo: nao gravado (somente tela)"
    fi
    msg_info "Ctrl+C encerra e desativa o debug automaticamente."
    printf '\n'
    if command -v journalctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        journalctl -kf -n0 -o short-precise | grep -i 'wireguard' | tee -a "$_lf"
    elif dmesg --help 2>&1 | grep -q -- '--follow'; then
        dmesg -w | grep -i 'wireguard' | tee -a "$_lf"
    elif [ -r /var/log/messages ]; then
        tail -n0 -f /var/log/messages | grep -i 'wireguard' | tee -a "$_lf"
    else
        msg_err "Nenhuma fonte de log do kernel com acompanhamento disponivel."
    fi
    debug_off
}

debug_menu() {
    printf '\n--- Debug / Troubleshooting ---\n'
    print_log_destinations
    printf -- '-----------------------------------------------------\n'
    printf ' 1) Captura guiada com relatorio (recomendado)\n'
    printf ' 2) Acompanhar log do kernel ao vivo\n'
    printf ' 3) Teste de MTU ate o endpoint\n'
    printf ' 4) Listar relatorios salvos\n'
    printf ' 5) Exibir ultimo relatorio\n'
    printf ' 6) Retencao de relatorios (atual: %s dias)\n' "$(setting_get RETENTION_DAYS 30)"
    printf ' 7) Status do debug\n'
    printf ' 8) Forcar desativacao do debug\n'
    printf ' 0) Voltar\n'
    ask _dopt "Opcao"
    case "$_dopt" in
        1) need_wg && debug_capture ;;
        2) debug_live ;;
        3) need_wg && mtu_test ;;
        4) list_reports ;;
        5) show_last_report ;;
        6) retention_menu ;;
        7) debug_status ;;
        8) debug_force_off ;;
        *) : ;;
    esac
}

# ----------------------------------------------------------------------------
# Utilitarios gerais
# ----------------------------------------------------------------------------
conf_get() {
    sed -n "s/^$1[[:space:]]*=[[:space:]]*//p" "$2" 2>/dev/null | head -n1
}

# Configuracao global (KEY=VALOR). Lida sem "source": evita execucao de codigo.
setting_get() {
    _sv=$(sed -n "s/^$1=//p" "$SETTINGS_FILE" 2>/dev/null | head -n1)
    case "$_sv" in ''|*[!0-9]*) printf '%s' "$2" ;; *) printf '%s' "$_sv" ;; esac
}

setting_set() {
    _stmp="$SETTINGS_FILE.tmp"
    { grep -v "^$1=" "$SETTINGS_FILE" 2>/dev/null; printf '%s=%s\n' "$1" "$2"; } > "$_stmp"
    mv "$_stmp" "$SETTINGS_FILE" && chmod 600 "$SETTINGS_FILE"
}

state_get() {
    _sg=$(cat "$RUN_DIR/$1.$2" 2>/dev/null)
    case "$_sg" in ''|*[!0-9]*) printf '%s' "$3" ;; *) printf '%s' "$_sg" ;; esac
}

state_set() {
    mkdir -p "$RUN_DIR" && chmod 700 "$RUN_DIR"
    printf '%s\n' "$3" > "$RUN_DIR/$1.$2"
}

monitor_get() {
    _mg=$(sed -n "s/^$2=//p" "$WG_DIR/$1/monitor.conf" 2>/dev/null | head -n1)
    case "$_mg" in ''|*[!0-9]*) printf '%s' "$3" ;; *) printf '%s' "$_mg" ;; esac
}

# Log de eventos do agente: arquivo local + journal (systemd) ou syslog (cron)
mlog() {
    mkdir -p "$LOG_DIR" && chmod 700 "$LOG_DIR"
    _ml="$LOG_DIR/maintenance.log"
    if [ -f "$_ml" ] && [ "$(wc -c < "$_ml")" -gt 1048576 ]; then mv "$_ml" "$_ml.1"; fi
    _mm="$(date '+%Y-%m-%d %H:%M:%S') [$1] $2"
    printf '%s\n' "$_mm" >> "$_ml"; chmod 600 "$_ml"
    printf '%s\n' "$_mm"
    if [ -z "${INVOCATION_ID:-}" ] && command -v logger >/dev/null 2>&1; then
        logger -t wg-client-manager -- "[$1] $2" 2>/dev/null
    fi
}

acquire_lock() {
    mkdir -p "$RUN_DIR" && chmod 700 "$RUN_DIR"
    if mkdir "$LOCK_DIR" 2>/dev/null; then
        printf '%s\n' "$$" > "$LOCK_DIR/pid"; LOCK_HELD=1; return 0
    fi
    _lp=$(cat "$LOCK_DIR/pid" 2>/dev/null)
    if [ -n "$_lp" ] && kill -0 "$_lp" 2>/dev/null; then return 1; fi
    rm -rf "$LOCK_DIR"
    mkdir "$LOCK_DIR" 2>/dev/null || return 1
    printf '%s\n' "$$" > "$LOCK_DIR/pid"; LOCK_HELD=1
}

resolve_host() {
    _rh=""
    if command -v getent >/dev/null 2>&1; then
        _rh=$(getent ahostsv4 "$1" 2>/dev/null | awk 'NR==1{print $1}')
        [ -z "$_rh" ] && _rh=$(getent hosts "$1" 2>/dev/null | awk 'NR==1{print $1}')
    fi
    if [ -z "$_rh" ] && command -v nslookup >/dev/null 2>&1; then
        _rh=$(nslookup "$1" 2>/dev/null | awk '/^Name:/{f=1;next} f&&/^Address/{if($1=="Address:")print $2; else print $3; exit}')
    fi
    [ -n "$_rh" ] || return 1
    printf '%s' "$_rh"
}

# Endpoint do .conf -> _ep_host / _ep_port
parse_endpoint() {
    _ep=$(conf_get Endpoint "$WG_DIR/$1/$1.conf")
    _ep_port=${_ep##*:}
    _ep_host=${_ep%:*}; _ep_host=${_ep_host#[}; _ep_host=${_ep_host%]}
}

# ----------------------------------------------------------------------------
# Backup e rollback
# ----------------------------------------------------------------------------
backup_tunnel() {
    _bt="$WG_DIR/$1/.backup"
    _bd="$_bt/$(date '+%Y%m%d-%H%M%S')-$2"
    mkdir -p "$_bd" && chmod 700 "$_bt" "$_bd" || return 1
    for _bf in privatekey publickey presharedkey "$1.conf"; do
        [ -f "$WG_DIR/$1/$_bf" ] && cp -p "$WG_DIR/$1/$_bf" "$_bd/"
    done
    chmod 600 "$_bd"/* 2>/dev/null
    # shellcheck disable=SC2012
    ls -1dt "$_bt"/*/ 2>/dev/null | tail -n +"$((BACKUP_KEEP + 1))" | while IFS= read -r _old_bk; do
        rm -rf "$_old_bk"
    done
    printf '%s' "$_bd"
}

rollback_tunnel() {
    select_tunnel _rb || return 1
    _bt="$WG_DIR/$_rb/.backup"
    # shellcheck disable=SC2012
    _list=$(ls -1dt "$_bt"/*/ 2>/dev/null)
    if [ -z "$_list" ]; then
        msg_info "Nenhum backup para '$_rb'. Backups sao criados antes de rotacao, PSK, MTU e atualizacao via CLI."
        return 0
    fi
    printf '\n--- Backups de %s (mais recente primeiro, mantidos: %s) ---\n' "$_rb" "$BACKUP_KEEP"
    printf '%s\n' "$_list" | awk '{n=split($0,a,"/"); printf "  %d) %s\n", NR, a[n-1]}'
    _cnt=$(printf '%s\n' "$_list" | wc -l)
    while :; do
        ask _sel_bk "Restaurar qual" "1"
        case "$_sel_bk" in ''|*[!0-9]*) ;; *) [ "$_sel_bk" -ge 1 ] && [ "$_sel_bk" -le "$_cnt" ] && break ;; esac
        msg_err "Escolha entre 1 e $_cnt."
    done
    _src=$(printf '%s\n' "$_list" | sed -n "${_sel_bk}p"); _src=${_src%/}
    confirm "Restaurar '$(basename "$_src")' em '$_rb'?" || { msg_info "Cancelado."; return 0; }

    _d="$WG_DIR/$_rb"
    _cur=$(tr -d ' \t\r\n' < "$_d/publickey")
    _pre=$(backup_tunnel "$_rb" antes-rollback)
    for _bf in privatekey publickey "$_rb.conf"; do
        cp -p "$_src/$_bf" "$_d/$_bf" || { msg_err "Falha ao restaurar $_bf."; return 1; }
    done
    if [ -f "$_src/presharedkey" ]; then cp -p "$_src/presharedkey" "$_d/presharedkey"; else rm -f "$_d/presharedkey"; fi
    chmod 600 "$_d/privatekey" "$_d/publickey" "$_d/$_rb.conf"
    _res=$(tr -d ' \t\r\n' < "$_d/publickey")
    msg_ok "Restaurado. Estado anterior salvo em $_pre (rollback tambem e reversivel)."

    if [ "$_cur" != "$_res" ]; then
        printf '\nA chave publica mudou. No SERVIDOR:\n'
        printf '/interface wireguard peers set [find public-key="%s"] public-key="%s"\n' "$_cur" "$_res"
        printf '/interface wireguard peers print detail where public-key="%s"\n\n' "$_res"
    fi
    if tunnel_is_up "$_rb"; then
        wg-quick down "$_rb" >/dev/null 2>&1
        tunnel_up "$_rb"
    fi
}

# ----------------------------------------------------------------------------
# Agente de manutencao: DDNS + watchdog + retencao
# ----------------------------------------------------------------------------
# Re-resolve o endpoint e atualiza com "wg set" (sem derrubar a sessao).
# Retorna 0 somente se o endpoint foi alterado.
reresolve_endpoint() {
    parse_endpoint "$1"
    valid_ip "$_ep_host" && return 1
    if ! _rr_new=$(resolve_host "$_ep_host"); then
        mlog "$1" "DDNS: falha ao resolver $_ep_host"
        return 1
    fi
    _rr_cur=$(wg show "$1" endpoints 2>/dev/null | awk 'NR==1{print $2}')
    _rr_cur=${_rr_cur%:*}; _rr_cur=${_rr_cur#[}; _rr_cur=${_rr_cur%]}
    [ "$_rr_new" = "$_rr_cur" ] && return 1
    _rr_peer=$(wg show "$1" peers 2>/dev/null | head -n1)
    [ -n "$_rr_peer" ] || return 1
    case "$_rr_new" in *:*) _rr_fmt="[$_rr_new]" ;; *) _rr_fmt=$_rr_new ;; esac
    if wg set "$1" peer "$_rr_peer" endpoint "$_rr_fmt:$_ep_port"; then
        mlog "$1" "DDNS: $_ep_host mudou de ${_rr_cur:-nenhum} para $_rr_new; endpoint atualizado sem reiniciar"
        return 0
    fi
    mlog "$1" "DDNS: falha ao aplicar novo endpoint $_rr_new"
    return 1
}

maint_tunnel() {
    _mt=$1
    [ "$(monitor_get "$_mt" ENABLED 0)" = "1" ] || return 0
    [ -f "$WG_DIR/$_mt/.admin-down" ] && return 0
    _mnow=$(date +%s)
    _mhsmax=$(monitor_get "$_mt" HS_MAX 180)
    _mback=$(monitor_get "$_mt" BACKOFF 300)
    _mlr=$(state_get "$_mt" last_restart 0)

    if ! tunnel_is_up "$_mt"; then
        if [ $((_mnow - _mlr)) -ge "$_mback" ]; then
            mlog "$_mt" "tunel inativo sem desligamento administrativo: subindo"
            if wg-quick up "$_mt" >/dev/null 2>&1; then
                mlog "$_mt" "tunel ativo"
                state_set "$_mt" last_up "$_mnow"
            else
                mlog "$_mt" "falha ao subir o tunel (nova tentativa em ${_mback}s)"
            fi
            state_set "$_mt" last_restart "$_mnow"
        fi
        return 0
    fi

    _mhs=$(wg show "$_mt" latest-handshakes 2>/dev/null | awk 'NR==1{print $2}')
    _mhs=${_mhs:-0}
    if [ "$_mhs" -gt 0 ]; then
        _mage=$((_mnow - _mhs))
    else
        _mlu=$(state_get "$_mt" last_up 0)
        if [ "$_mlu" -eq 0 ]; then state_set "$_mt" last_up "$_mnow"; return 0; fi
        _mage=$((_mnow - _mlu))
    fi

    # Saudavel: handshake renovado recentemente (rekey a cada ~2 min com trafego/keepalive)
    [ "$_mage" -le 135 ] && return 0

    # 1o DDNS: IP publico do servidor mudou? Corrige sem reiniciar.
    if [ "$(monitor_get "$_mt" DDNS 1)" = "1" ] && reresolve_endpoint "$_mt"; then
        return 0
    fi

    # 2o watchdog: handshake velho e fora do backoff -> reinicia
    if [ "$(monitor_get "$_mt" WATCHDOG 1)" = "1" ] && [ "$_mage" -gt "$_mhsmax" ] &&
       [ $((_mnow - _mlr)) -ge "$_mback" ]; then
        mlog "$_mt" "watchdog: sem handshake ha ${_mage}s (limite ${_mhsmax}s): reiniciando tunel"
        wg-quick down "$_mt" >/dev/null 2>&1
        if wg-quick up "$_mt" >/dev/null 2>&1; then
            mlog "$_mt" "watchdog: tunel reiniciado"
        else
            mlog "$_mt" "watchdog: falha ao subir apos reinicio"
        fi
        state_set "$_mt" last_restart "$_mnow"
        state_set "$_mt" last_up "$_mnow"
    fi
}

apply_retention() {
    _rdays=$(setting_get RETENTION_DAYS 30)
    [ -d "$LOG_DIR" ] || { printf '0'; return 0; }
    find "$LOG_DIR" -maxdepth 1 -type f \( -name '*.log' -o -name '*.log.1' \) ! -name 'maintenance.log' \
        -mtime +"$_rdays" -print -exec rm -f {} \; 2>/dev/null | wc -l | tr -d ' '
}

retention_daily() {
    _today=$(date +%Y%m%d)
    [ "$(state_get global retention_day 0)" = "$_today" ] && return 0
    _rem=$(apply_retention)
    state_set global retention_day "$_today"
    [ "${_rem:-0}" -gt 0 ] && mlog global "retencao: $_rem relatorio(s) com mais de $(setting_get RETENTION_DAYS 30) dias removido(s)"
    return 0
}

run_maintenance() {
    if ! acquire_lock; then
        printf 'Manutencao ja em execucao; ignorando.\n'
        return 0
    fi
    _mn=0
    for _mdir in "$WG_DIR"/*/; do
        [ -d "$_mdir" ] || continue
        _mname=$(basename "$_mdir")
        tunnel_exists "$_mname" || continue
        [ -f "$_mdir/monitor.conf" ] || continue
        _mn=$((_mn + 1))
        maint_tunnel "$_mname"
    done
    retention_daily
    release_lock
    [ -t 1 ] && msg_ok "Manutencao concluida: $_mn tunel(is) monitorado(s) verificado(s)."
    return 0
}

agent_installed() {
    [ -x "$AGENT_BIN" ] || return 1
    if [ "$(init_system)" = "systemd" ]; then
        systemctl is-enabled --quiet "$UNIT_NAME.timer" 2>/dev/null
    else
        grep -qs "$AGENT_BIN --maintenance" /etc/cron.d/wg-client-manager /etc/crontabs/root
    fi
}

install_agent() {
    _self=$(readlink -f "$0" 2>/dev/null || printf '%s' "$0")
    if [ ! -f "$_self" ]; then
        msg_err "Nao foi possivel localizar o proprio script ($0)."
        return 1
    fi
    if [ "$_self" != "$AGENT_BIN" ]; then
        mkdir -p "$(dirname "$AGENT_BIN")"
        cp "$_self" "$AGENT_BIN.tmp" && chown root:root "$AGENT_BIN.tmp" 2>/dev/null
        if ! { chmod 700 "$AGENT_BIN.tmp" && mv "$AGENT_BIN.tmp" "$AGENT_BIN"; }; then
            msg_err "Falha ao instalar $AGENT_BIN"; return 1
        fi
    fi
    msg_ok "Agente v$VERSION em $AGENT_BIN (root, 700)."
    mlog global "agente v$VERSION instalado em $AGENT_BIN" >/dev/null

    if [ "$(init_system)" = "systemd" ]; then
        cat > "$UNIT_DIR/$UNIT_NAME.service" <<EOF
# wg-client-manager v$VERSION - EdenCore
[Unit]
Description=wg-client-manager: manutencao WireGuard (DDNS, watchdog, retencao)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$AGENT_BIN --maintenance
# Seguranca por Design: precisa de root/CAP_NET_ADMIN para "wg set" e "wg-quick";
# demais superficies restritas.
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=true
Nice=10
EOF
        cat > "$UNIT_DIR/$UNIT_NAME.timer" <<EOF
# wg-client-manager v$VERSION - EdenCore
[Unit]
Description=wg-client-manager: manutencao a cada 1 minuto

[Timer]
OnBootSec=2min
OnUnitActiveSec=1min
AccuracySec=10s

[Install]
WantedBy=timers.target
EOF
        chmod 644 "$UNIT_DIR/$UNIT_NAME.service" "$UNIT_DIR/$UNIT_NAME.timer"
        if systemctl daemon-reload && systemctl enable --now "$UNIT_NAME.timer" >/dev/null 2>&1; then
            msg_ok "Timer systemd $UNIT_NAME.timer ativo (a cada 1 min)."
        else
            msg_err "Falha ao ativar o timer."; return 1
        fi
    else
        _cronline="* * * * * $AGENT_BIN --maintenance >/dev/null 2>&1"
        if [ -d /etc/cron.d ]; then
            printf '# wg-client-manager v%s - EdenCore\n* * * * * root %s --maintenance >/dev/null 2>&1\n' "$VERSION" "$AGENT_BIN" > /etc/cron.d/wg-client-manager
            chmod 644 /etc/cron.d/wg-client-manager
            msg_ok "Cron instalado em /etc/cron.d/wg-client-manager (a cada 1 min)."
        elif [ -f /etc/crontabs/root ] || [ -d /etc/crontabs ]; then
            grep -qs "$AGENT_BIN --maintenance" /etc/crontabs/root || printf '%s\n' "$_cronline" >> /etc/crontabs/root
            msg_ok "Cron instalado em /etc/crontabs/root (a cada 1 min)."
        else
            msg_err "Nem systemd nem cron encontrados. Agende manualmente: $_cronline"
            return 1
        fi
        msg_info "Confirme que o servico cron (crond/cronie) esta ativo e habilitado no boot."
    fi
}

remove_agent() {
    if [ "$(init_system)" = "systemd" ]; then
        systemctl disable --now "$UNIT_NAME.timer" >/dev/null 2>&1
        rm -f "$UNIT_DIR/$UNIT_NAME.timer" "$UNIT_DIR/$UNIT_NAME.service"
        systemctl daemon-reload 2>/dev/null
    fi
    rm -f /etc/cron.d/wg-client-manager
    if [ -f /etc/crontabs/root ]; then
        grep -v "$AGENT_BIN --maintenance" /etc/crontabs/root > /etc/crontabs/root.tmp && mv /etc/crontabs/root.tmp /etc/crontabs/root
    fi
    rm -f "$AGENT_BIN"
    mlog global "agente removido" >/dev/null
    msg_ok "Agente removido. Tuneis e configuracoes de monitoramento foram mantidos."
}

# Com trafego, o WireGuard renova o handshake apos 120s (REKEY_AFTER_TIME), no
# proximo pacote. Com keepalive K, a idade normal chega a 120+K. Margem: 30s.
hs_min_safe() {
    _k=$(conf_get PersistentKeepalive "$WG_DIR/$1/$1.conf")
    case "$_k" in ''|*[!0-9]*) _k=0 ;; esac
    _m=$((120 + _k + 30)); [ "$_m" -lt 180 ] && _m=180
    printf '%s' "$_m"
}

monitor_enable() {
    select_tunnel _me || return 1
    _ka=$(conf_get PersistentKeepalive "$WG_DIR/$_me/$_me.conf")
    _wd=1
    if [ -z "$_ka" ] || [ "$_ka" = "0" ]; then
        msg_warn "PersistentKeepalive desativado: sem trafego o handshake envelhece e o watchdog reiniciaria o tunel sem motivo."
        msg_warn "Watchdog sera DESATIVADO neste tunel; DDNS continua ativo."
        _wd=0
    fi
    while :; do
        _hmin=$(hs_min_safe "$_me")
        ask _hsm "Reiniciar se sem handshake por mais de N segundos (${_hmin}-3600)" "$_hmin"
        case "$_hsm" in ''|*[!0-9]*) ;; *) [ "$_hsm" -ge "$_hmin" ] && [ "$_hsm" -le 3600 ] && break ;; esac
        msg_err "Valor entre ${_hmin} e 3600: com keepalive atual, handshake saudavel chega a $((_hmin - 30))s."
    done
    parse_endpoint "$_me"
    _dd=1; valid_ip "$_ep_host" && _dd=0
    printf 'ENABLED=1\nHS_MAX=%s\nDDNS=%s\nWATCHDOG=%s\nBACKOFF=300\n' "$_hsm" "$_dd" "$_wd" > "$WG_DIR/$_me/monitor.conf"
    chmod 600 "$WG_DIR/$_me/monitor.conf"
    msg_ok "Monitoramento ativo em '$_me' (DDNS=$_dd, WATCHDOG=$_wd, limite=${_hsm}s)."
    mlog "$_me" "monitoramento ativado (DDNS=$_dd, WATCHDOG=$_wd, limite=${_hsm}s)" >/dev/null
    [ "$_dd" -eq 0 ] && msg_info "Endpoint e IP fixo ($_ep_host): re-resolucao DDNS nao se aplica."
    if agent_installed; then
        msg_info "Agente ja instalado. Se atualizou o script, reinstale pela opcao 5 para alinhar a versao."
    else
        install_agent
    fi
}

monitor_disable() {
    select_tunnel _md || return 1
    rm -f "$WG_DIR/$_md/monitor.conf"
    mlog "$_md" "monitoramento desativado" >/dev/null
    msg_ok "Monitoramento desativado em '$_md'."
}

monitor_status() {
    printf '\n--- Monitoramento automatico ---\n'
    if agent_installed; then
        msg_ok "Agente instalado: $("$AGENT_BIN" --version 2>/dev/null) | script atual: v$VERSION"
        if [ "$(init_system)" = "systemd" ]; then
            _nx=$(systemctl list-timers --all --no-legend --no-pager "$UNIT_NAME.timer" 2>/dev/null | awk 'NR==1{print $1, $2, $3, $4}')
            msg_info "Timer: $(systemctl is-active "$UNIT_NAME.timer" 2>/dev/null) | proxima execucao: ${_nx:-n/d}"
        fi
    else
        msg_warn "Agente NAO instalado: DDNS e watchdog nao estao rodando."
    fi
    printf '\n%-16s %-6s %-5s %-5s %-9s %s\n' "TUNEL" "ESTADO" "DDNS" "WDOG" "HANDSHAKE" "ENDPOINT ATUAL"
    for _sd in "$WG_DIR"/*/; do
        [ -d "$_sd" ] || continue
        _sn=$(basename "$_sd")
        tunnel_exists "$_sn" || continue
        [ -f "$_sd/monitor.conf" ] || continue
        if tunnel_is_up "$_sn"; then
            _st="UP"
            _sh=$(wg show "$_sn" latest-handshakes 2>/dev/null | awk 'NR==1{print $2}')
            if [ "${_sh:-0}" -gt 0 ]; then _sa="$(( $(date +%s) - _sh ))s"; else _sa="nunca"; fi
            _se=$(wg show "$_sn" endpoints 2>/dev/null | awk 'NR==1{print $2}')
        else
            _st="DOWN"; _sa="-"; _se="-"
        fi
        [ -f "$_sd/.admin-down" ] && _st="ADM-OFF"
        if [ "$(monitor_get "$_sn" HS_MAX 180)" -lt "$(hs_min_safe "$_sn")" ]; then
            _lowhs="${_lowhs:-}$_sn (limite $(monitor_get "$_sn" HS_MAX 180)s < seguro $(hs_min_safe "$_sn")s) "
        fi
        printf '%-16s %-6s %-5s %-5s %-9s %s\n' "$_sn" "$_st" "$(monitor_get "$_sn" DDNS 0)" "$(monitor_get "$_sn" WATCHDOG 0)" "$_sa" "$_se"
    done
    if [ -n "${_lowhs:-}" ]; then
        msg_warn "Limite de watchdog abaixo do seguro: ${_lowhs}. Reative pelo menu 15 > 1."
        _lowhs=""
    fi
    printf '\nUltimos eventos (%s/maintenance.log):\n' "$LOG_DIR"
    tail -n 10 "$LOG_DIR/maintenance.log" 2>/dev/null || printf '  (sem eventos)\n'
}

# ----------------------------------------------------------------------------
# Firewall local (somente leitura) e testes controlados
# ----------------------------------------------------------------------------
# ufw e firewalld sao front-ends; por baixo o kernel usa nftables ou iptables
# (legacy ou nf_tables). O script apenas LE esse estado para diagnostico.
detect_firewall() {
    _fw=""
    if command -v ufw >/dev/null 2>&1; then
        if ufw status 2>/dev/null | grep -qi 'status: active'; then _fw="ufw (ativo)"; else _fw="ufw (inativo)"; fi
    fi
    if command -v firewall-cmd >/dev/null 2>&1; then
        if firewall-cmd --state >/dev/null 2>&1; then _f2="firewalld (ativo)"; else _f2="firewalld (inativo)"; fi
        _fw="${_fw:+$_fw, }$_f2"
    fi
    _be=""
    if command -v iptables >/dev/null 2>&1; then
        case "$(iptables -V 2>/dev/null)" in
            *nf_tables*) _be="iptables-nft" ;;
            *legacy*)    _be="iptables-legacy" ;;
            *)           _be="iptables" ;;
        esac
    fi
    if command -v nft >/dev/null 2>&1; then
        _nr=$(nft list ruleset 2>/dev/null | grep -c '^table')
        _be="${_be:+$_be, }nftables ($_nr tabela(s))"
    fi
    printf '%s' "${_fw:-sem front-end (ufw/firewalld)}${_be:+ | backend: $_be}"
}

log_lines() {
    if [ -f "$LOG_DIR/maintenance.log" ]; then wc -l < "$LOG_DIR/maintenance.log" | tr -d ' '; else printf '0'; fi
}
log_new()   { tail -n +"$(( $1 + 1 ))" "$LOG_DIR/maintenance.log" 2>/dev/null; }

test_preflight() {
    if ! agent_installed; then msg_err "Agente nao instalado (menu 15 > 5)."; return 1; fi
    if [ "$(monitor_get "$1" ENABLED 0)" != "1" ]; then msg_err "Monitoramento inativo em '$1' (menu 15 > 1)."; return 1; fi
    if ! tunnel_is_up "$1"; then msg_err "Tunel '$1' inativo."; return 1; fi
    return 0
}

# Teste de DDNS: aponta o endpoint para um IP de documentacao (RFC 5737/3849)
# e espera o agente re-resolver o nome. Nao envia trafego a terceiros.
test_ddns() {
    select_tunnel _td || return 1
    test_preflight "$_td" || return 1
    parse_endpoint "$_td"
    if valid_ip "$_ep_host" || [ "$(monitor_get "$_td" DDNS 0)" != "1" ]; then
        msg_err "Endpoint com IP fixo ou DDNS desativado: teste nao se aplica."; return 1
    fi
    _peer=$(wg show "$_td" peers | head -n1)
    _orig=$(wg show "$_td" endpoints | awk 'NR==1{print $2}')
    case "$_orig" in \[*) _fake="[2001:db8::1]:$_ep_port" ;; *) _fake="192.0.2.1:$_ep_port" ;; esac

    msg_warn "Se o SERVIDOR tiver persistent-keepalive neste peer, o roaming nativo do WireGuard"
    msg_warn "corrige o endpoint antes do agente e o teste fica inconclusivo. No MikroTik:"
    printf '  /interface wireguard peers print detail where public-key="%s"\n' "$(tr -d ' \t\r\n' < "$WG_DIR/$_td/publickey")"
    msg_info "Duracao maxima: 6 min. Endpoint original restaurado ao fim, em erro ou Ctrl+C."
    confirm "Iniciar teste de DDNS em '$_td'?" || return 0

    _l0=$(log_lines)
    TEST_EP_TUN=$_td; TEST_EP_PEER=$_peer; TEST_EP_ORIG=$_orig
    wg set "$_td" peer "$_peer" endpoint "$_fake" || { TEST_EP_TUN=""; msg_err "Falha ao aplicar endpoint de teste."; return 1; }
    mlog "$_td" "teste DDNS: endpoint temporario $_fake (original $_orig)" >/dev/null

    _t=0; _res=""
    while [ "$_t" -lt 360 ]; do
        sleep 5; _t=$((_t + 5))
        if log_new "$_l0" | grep -q 'DDNS: .*endpoint atualizado'; then _res=ok; break; fi
        _now_ep=$(wg show "$_td" endpoints | awk 'NR==1{print $2}')
        if [ "$_now_ep" != "$_fake" ]; then _res=roaming; break; fi
        printf '\r  %3ss | endpoint %s' "$_t" "$_now_ep"
    done
    printf '\n'
    case "$_res" in
        ok)
            TEST_EP_TUN=""
            msg_ok "DDNS validado: agente re-resolveu e corrigiu o endpoint sem reiniciar."
            log_new "$_l0" | grep 'DDNS' ;;
        roaming)
            TEST_EP_TUN=""
            msg_warn "Endpoint corrigido SEM evento do agente: roaming nativo (servidor enviou pacote)."
            msg_warn "Inconclusivo. Zere o persistent-keepalive do peer no servidor e repita." ;;
        *)
            test_cleanup
            msg_err "Sem correcao em 6 min. Endpoint original restaurado. Verifique: journalctl -u $UNIT_NAME" ;;
    esac
    mlog "$_td" "teste DDNS finalizado: ${_res:-timeout}" >/dev/null
}

# Teste de watchdog: rota blackhole temporaria ate o endpoint (iproute2).
# Independe de ufw/firewalld/nftables/iptables e nao altera nenhuma regra.
test_watchdog() {
    select_tunnel _tw || return 1
    test_preflight "$_tw" || return 1
    if [ "$(monitor_get "$_tw" WATCHDOG 0)" != "1" ]; then msg_err "Watchdog desativado em '$_tw'."; return 1; fi
    _ip=$(wg show "$_tw" endpoints | awk 'NR==1{print $2}')
    _ip=${_ip%:*}; _ip=${_ip#[}; _ip=${_ip%]}
    valid_ip "$_ip" || { msg_err "Endpoint atual indisponivel."; return 1; }
    case "$_ip" in *:*) _fam=-6; _pfx="$_ip/128" ;; *) _fam=-4; _pfx="$_ip/32" ;; esac
    if ip "$_fam" route show "$_pfx" 2>/dev/null | grep -q .; then
        msg_err "Ja existe rota especifica para $_pfx; teste abortado para nao interferir."; return 1
    fi
    _hsmax=$(monitor_get "$_tw" HS_MAX 180)
    _lr=$(state_get "$_tw" last_restart 0)
    _wait_bk=$(( $(monitor_get "$_tw" BACKOFF 300) - ($(date +%s) - _lr) ))
    msg_warn "Durante o teste, TODO trafego deste host para $_ip fica bloqueado (rota blackhole)."
    msg_info "Evento esperado em ~$((_hsmax + 60))s. Duracao maxima: 8 min. Rota removida ao fim, em erro ou Ctrl+C."
    [ "$_wait_bk" -gt 0 ] && msg_info "Houve reinicio recente: o watchdog aguarda mais ${_wait_bk}s de backoff."
    confirm "Iniciar teste de watchdog em '$_tw'?" || return 0

    _l0=$(log_lines)
    ip "$_fam" route add blackhole "$_pfx" || { msg_err "Falha ao criar rota de teste."; return 1; }
    TEST_ROUTE=$_pfx; TEST_ROUTE_FAM=$_fam
    mlog "$_tw" "teste watchdog: rota blackhole temporaria para $_pfx" >/dev/null

    _t=0; _res=""
    while [ "$_t" -lt 480 ]; do
        sleep 5; _t=$((_t + 5))
        if log_new "$_l0" | grep -q 'watchdog: tunel reiniciado'; then _res=ok; break; fi
        if log_new "$_l0" | grep -q 'watchdog: falha'; then _res=falha; break; fi
        _hs=$(wg show "$_tw" latest-handshakes 2>/dev/null | awk 'NR==1{print $2}')
        if [ "${_hs:-0}" -gt 0 ]; then _age="$(( $(date +%s) - _hs ))s"; else _age="-"; fi
        printf '\r  %3ss | handshake ha %s   ' "$_t" "$_age"
    done
    printf '\n'
    test_cleanup
    mlog "$_tw" "teste watchdog: rota removida" >/dev/null
    msg_ok "Rota de teste removida."

    case "$_res" in
        ok)    msg_ok "Watchdog validado: reinicio executado pelo agente."
               log_new "$_l0" | grep 'watchdog' ;;
        falha) msg_err "Watchdog reiniciou mas o wg-quick falhou ao subir. Veja: journalctl -u $UNIT_NAME" ;;
        *)     msg_err "Sem reinicio em 8 min. Verifique: journalctl -u $UNIT_NAME e systemctl list-timers" ;;
    esac

    printf 'Aguardando handshake apos remover o bloqueio'
    _sip=$(server_tunnel_ip "$_tw")
    _i=0
    while [ "$_i" -lt 60 ]; do
        [ -n "$_sip" ] && ping -c1 -W1 "$_sip" >/dev/null 2>&1
        _hs=$(wg show "$_tw" latest-handshakes 2>/dev/null | awk 'NR==1{print $2}')
        if [ "${_hs:-0}" -gt 0 ] && [ $(( $(date +%s) - _hs )) -lt 30 ]; then break; fi
        printf '.'; sleep 2; _i=$((_i + 2))
    done
    printf '\n'
    if [ "$_i" -lt 60 ]; then msg_ok "Tunel recuperado."; else msg_warn "Handshake ainda nao renovado; rode o diagnostico (menu 10)."; fi
    mlog "$_tw" "teste watchdog finalizado: ${_res:-timeout}" >/dev/null
}

monitor_menu() {
    printf '\n--- Monitoramento automatico (DDNS + watchdog) ---\n'
    printf 'Eventos: %s/maintenance.log e %s\n' "$LOG_DIR" \
        "$([ "$(init_system)" = systemd ] && echo "journalctl -u $UNIT_NAME" || echo "syslog (logger)")"
    printf -- '-----------------------------------------------------\n'
    printf ' 1) Ativar monitoramento em um tunel\n'
    printf ' 2) Desativar monitoramento em um tunel\n'
    printf ' 3) Status e ultimos eventos\n'
    printf ' 4) Executar manutencao agora\n'
    printf ' 5) Instalar/atualizar agente (timer)\n'
    printf ' 6) Remover agente (timer)\n'
    printf ' 7) Teste controlado do DDNS\n'
    printf ' 8) Teste controlado do watchdog\n'
    printf ' 0) Voltar\n'
    ask _mo "Opcao"
    case "$_mo" in
        1) need_wg && monitor_enable ;;
        2) monitor_disable ;;
        3) monitor_status ;;
        4) need_wg && run_maintenance ;;
        5) install_agent ;;
        6) confirm "Remover agente e timer?" && remove_agent ;;
        7) need_wg && test_ddns ;;
        8) need_wg && test_watchdog ;;
        *) : ;;
    esac
}

# ----------------------------------------------------------------------------
# Teste de MTU (Path MTU com bit DF ate o endpoint)
# ----------------------------------------------------------------------------
ping_df_supported() {
    ping -c1 -W1 -M "do" -s 16 127.0.0.1 >/dev/null 2>&1
}

# ping_df ALVO PAYLOAD FAMILIA(4|6)
ping_df() {
    if [ "$3" = "6" ]; then
        ping -6 -c2 -i 0.2 -W1 -M "do" -s "$2" "$1" >/dev/null 2>&1
    else
        ping -c2 -i 0.2 -W1 -M "do" -s "$2" "$1" >/dev/null 2>&1
    fi
}

# conf_set_iface ARQ CHAVE VALOR -> define/remove chave no [Interface] (valores nao secretos)
conf_set_iface() {
    _cf=$1; _ct="$1.tmp"
    while IFS= read -r _l || [ -n "$_l" ]; do
        case "$_l" in
            "$2"*=*) ;;
            Address*=*)
                printf '%s\n' "$_l"
                [ -n "$3" ] && printf '%s = %s\n' "$2" "$3" ;;
            *) printf '%s\n' "$_l" ;;
        esac
    done < "$_cf" > "$_ct" && mv "$_ct" "$_cf" && chmod 600 "$_cf"
}

mtu_test() {
    select_tunnel _mu || return 1
    if ! ping_df_supported; then
        msg_err "ping sem suporte a '-M do' (busybox). Instale iputils (ex.: apk add iputils)."
        return 1
    fi
    parse_endpoint "$_mu"
    _mtarget=""
    if tunnel_is_up "$_mu"; then
        _mtarget=$(wg show "$_mu" endpoints 2>/dev/null | awk 'NR==1{print $2}')
        _mtarget=${_mtarget%:*}; _mtarget=${_mtarget#[}; _mtarget=${_mtarget%]}
        [ "$_mtarget" = "(none)" ] && _mtarget=""
    fi
    if [ -z "$_mtarget" ]; then
        if valid_ip "$_ep_host"; then _mtarget=$_ep_host; else _mtarget=$(resolve_host "$_ep_host"); fi
    fi
    [ -n "$_mtarget" ] || { msg_err "Nao foi possivel determinar o IP do endpoint."; return 1; }
    case "$_mtarget" in *:*) _mf=6; _mhdr=48; _movh=80 ;; *) _mf=4; _mhdr=28; _movh=60 ;; esac

    _approx=0
    if ! ping_df "$_mtarget" 16 "$_mf"; then
        msg_warn "Endpoint $_mtarget nao responde ICMP (comum: firewall de borda bloqueia ping na WAN)."
        if [ "$_mf" = "4" ] && confirm "Medir contra 1.1.1.1 como aproximacao do MTU do seu link?"; then
            _mtarget=1.1.1.1; _approx=1
            ping_df "$_mtarget" 16 4 || { msg_err "1.1.1.1 tambem nao responde. Teste impossivel agora."; return 1; }
        else
            return 1
        fi
    fi

    msg_info "Medindo Path MTU ate $_mtarget (DF ligado)..."
    _lo=$((1280 - _mhdr)); _hi=$((1500 - _mhdr))
    if ! ping_df "$_mtarget" "$_lo" "$_mf"; then
        msg_err "Nem $((_lo + _mhdr)) bytes passam sem fragmentar. Caminho muito restrito; verifique o link."
        return 1
    fi
    if ping_df "$_mtarget" "$_hi" "$_mf"; then
        _lo=$_hi
    else
        while [ "$_lo" -lt "$_hi" ]; do
            _mid=$(( (_lo + _hi + 1) / 2 ))
            if ping_df "$_mtarget" "$_mid" "$_mf"; then _lo=$_mid; else _hi=$((_mid - 1)); fi
        done
    fi
    _pmtu=$((_lo + _mhdr))
    _sug=$((_pmtu - _movh))
    if tunnel_is_up "$_mu"; then _curm=$(cat "/sys/class/net/$_mu/mtu" 2>/dev/null); else _curm=$(conf_get MTU "$WG_DIR/$_mu/$_mu.conf"); fi
    _curm=${_curm:-1420}

    printf '\nPath MTU ate %s%s : %s bytes\n' "$_mtarget" "$([ "$_approx" -eq 1 ] && echo ' (aproximacao)')" "$_pmtu"
    printf 'Overhead WireGuard (endpoint IPv%s) : %s bytes\n' "$_mf" "$_movh"
    printf 'MTU recomendado do tunel          : %s\n' "$_sug"
    printf 'MTU atual do tunel                : %s\n\n' "$_curm"

    if [ "$_sug" -lt 1280 ]; then
        msg_warn "Recomendado abaixo de 1280: IPv6 dentro do tunel nao funcionara. Use 1280 e revise o link."
        _sug=1280
    fi
    if [ "$_curm" -le "$_sug" ]; then
        msg_ok "MTU atual adequado ao caminho."
        return 0
    fi
    msg_warn "MTU atual ($_curm) acima do caminho: pacotes grandes fragmentam ou somem (ping OK, SSH/HTTPS trava)."
    if confirm "Gravar MTU = $_sug no .conf (com backup) e reiniciar o tunel?"; then
        _bk=$(backup_tunnel "$_mu" antes-mtu) && msg_info "Backup: $_bk"
        conf_set_iface "$WG_DIR/$_mu/$_mu.conf" MTU "$_sug"
        msg_ok "MTU = $_sug gravado."
        if tunnel_is_up "$_mu"; then wg-quick down "$_mu" >/dev/null 2>&1; tunnel_up "$_mu"; fi
    fi
}

retention_menu() {
    _cur=$(setting_get RETENTION_DAYS 30)
    msg_info "Retencao atual: relatorios com mais de $_cur dias sao removidos (maintenance.log rotaciona em 1 MB)."
    while :; do
        ask _nd "Nova retencao em dias (1-3650)" "$_cur"
        case "$_nd" in ''|*[!0-9]*|0*) ;; *) [ "$_nd" -le 3650 ] && break ;; esac
        msg_err "Informe de 1 a 3650."
    done
    setting_set RETENTION_DAYS "$_nd"
    _rem=$(apply_retention)
    msg_ok "Retencao: $_nd dias. Removidos agora: ${_rem:-0}. Configuracao em $SETTINGS_FILE."
    agent_installed || msg_info "Sem agente instalado, a retencao roda a cada captura guiada ou por esta opcao."
}

# ----------------------------------------------------------------------------
# Modo nao interativo (idempotente)
# ----------------------------------------------------------------------------
usage() {
    cat <<EOF
wg-client-manager.sh v$VERSION - EdenCore (Instrutor: Daniel Selbach Figueiró)

Uso interativo : sudo sh wg-client-manager.sh
Uso automatizado:
  --create                       Cria ou converge um tunel (idempotente)
    --name NOME                  a-z 0-9 - _, inicia com letra, max 15 (obrigatorio)
    --endpoint HOST:PORTA        IPv4, [IPv6] ou FQDN; porta padrao 51820 (obrigatorio)
    --server-pubkey CHAVE        chave publica do servidor (obrigatorio)
    --address CIDR[,CIDR]        IP do cliente no tunel (obrigatorio)
    --allowed-ips CIDR[,CIDR]    redes roteadas pela VPN (obrigatorio)
    --server-tunnel-ip IP        IP do servidor no tunel (vira /32 no AllowedIPs)
    --psk-file ARQ | --psk-stdin PSK gerada no servidor (nunca como argumento)
    --dns IP[,IP]  --keepalive N (padrao 25)  --mtu N
    --up  --boot  --monitor      sobe, habilita no boot, ativa DDNS+watchdog
    --strict                     falha se houver sobreposicao de rotas
  --show-pubkey NOME             imprime a chave publica do cliente
  --list                         lista tuneis
  --diagnose NOME                diagnostico de handshake
  --maintenance                  ciclo do agente (DDNS, watchdog, retencao)
  --install                      instala WireGuard e dependencias
  --version | --help

Saida de --create: linhas STATUS=changed|unchanged e PUBKEY=<chave publica>.
Codigos: 0 ok | 1 entrada invalida | 2 erro de execucao.
Ansible: changed_when: "'STATUS=changed' in resultado.stdout"
EOF
}

cli_die() { msg_err "$1"; exit "${2:-1}"; }

cli_create() {
    [ -n "$TUN" ] || cli_die "--name obrigatorio."
    valid_tunnel_name "$TUN" || cli_die "--name invalido: '$TUN'."
    [ -n "$EP_ARG" ] || cli_die "--endpoint obrigatorio."
    case "$EP_ARG" in
        \[*\]:*) _h=${EP_ARG%:*}; _h=${_h#[}; _h=${_h%]}; SRV_PORT=${EP_ARG##*:} ;;
        \[*\])   _h=${EP_ARG#[}; _h=${_h%]}; SRV_PORT=51820 ;;
        *:*:*)   cli_die "IPv6 no endpoint deve estar entre colchetes: [2001:db8::1]:51820" ;;
        *:*)     _h=${EP_ARG%:*}; SRV_PORT=${EP_ARG##*:} ;;
        *)       _h=$EP_ARG; SRV_PORT=51820 ;;
    esac
    if valid_ipv4 "$_h" || valid_fqdn "$_h"; then SRV_FMT=$_h
    elif valid_ipv6 "$_h"; then SRV_FMT="[$_h]"
    else cli_die "--endpoint com host invalido: '$_h'."; fi
    valid_port "$SRV_PORT" || cli_die "Porta invalida: '$SRV_PORT'."
    valid_wgkey "$SRV_PUB" || cli_die "--server-pubkey invalida."
    ADDR=$(normalize_list "$ADDR_IN" valid_cidr) || cli_die "--address invalido."
    ALLOWED=$(normalize_list "$ALLOWED_IN" valid_cidr) || cli_die "--allowed-ips invalido."
    if [ -n "$SRV_TIP" ]; then
        valid_ip "$SRV_TIP" || cli_die "--server-tunnel-ip invalido."
        ALLOWED=$(normalize_list "$ALLOWED, $(host_prefix "$SRV_TIP")" valid_cidr)
    fi
    DNS=""
    if [ -n "$DNS_IN" ]; then DNS=$(normalize_list "$DNS_IN" valid_ip) || cli_die "--dns invalido."; fi
    valid_keepalive "$KA" || cli_die "--keepalive invalido."
    if [ -n "$MTU" ]; then valid_mtu "$MTU" || cli_die "--mtu invalido (1280-9000)."; fi
    PSK=""
    if [ -n "$PSK_FILE" ]; then
        [ -r "$PSK_FILE" ] || cli_die "--psk-file ilegivel."
        PSK=$(tr -d ' \t\r\n' < "$PSK_FILE")
    elif [ "$PSK_STDIN" -eq 1 ]; then
        IFS= read -r PSK || true
        PSK=$(printf '%s' "$PSK" | tr -d ' \t\r\n')
    fi
    if [ -n "$PSK" ]; then valid_wgkey "$PSK" || cli_die "PSK invalida."; fi

    _conf_w=$(route_conflicts "$ALLOWED")
    if [ -n "$_conf_w" ]; then
        msg_warn "AllowedIPs sobrepoe rotas locais:" >&2
        printf '%s\n' "$_conf_w" >&2
        [ "$STRICT" -eq 1 ] && cli_die "Abortado por --strict."
    fi

    mkdir -p "$WG_DIR" && chmod 700 "$WG_DIR"
    _dir="$WG_DIR/$TUN"; _conf="$_dir/$TUN.conf"
    _changed=0
    if tunnel_exists "$TUN"; then
        # Converge: mantem a chave privada existente, compara o conteudo efetivo
        _new="$_dir/.desired.tmp"
        render_conf "$_dir/privatekey" > "$_new"
        if [ "$(grep -v '^# Gerado' "$_new")" = "$(grep -v '^# Gerado' "$_conf")" ]; then
            rm -f "$_new"
        else
            _bk=$(backup_tunnel "$TUN" antes-cli-update) || { rm -f "$_new"; cli_die "Falha no backup." 2; }
            mv "$_new" "$_conf" && chmod 600 "$_conf"
            if [ -n "$PSK" ]; then printf '%s\n' "$PSK" > "$_dir/presharedkey"; else rm -f "$_dir/presharedkey"; fi
            msg_info "Configuracao atualizada (backup: $_bk)." >&2
            _changed=1
            if tunnel_is_up "$TUN"; then wg-quick down "$TUN" >/dev/null 2>&1; wg-quick up "$TUN" >/dev/null 2>&1 || cli_die "Falha ao reiniciar $TUN." 2; fi
        fi
    else
        [ -e "$_dir" ] && cli_die "$_dir existe mas nao e um tunel valido. Remova manualmente." 2
        ip link show "$TUN" >/dev/null 2>&1 && cli_die "Ja existe interface de rede '$TUN'."
        mkdir -m 700 "$_dir" || cli_die "Falha ao criar $_dir" 2
        if ! { wg genkey > "$_dir/privatekey" && wg pubkey < "$_dir/privatekey" > "$_dir/publickey"; }; then
            rm -rf "$_dir"; cli_die "Falha ao gerar chaves." 2
        fi
        [ -n "$PSK" ] && printf '%s\n' "$PSK" > "$_dir/presharedkey"
        render_conf "$_dir/privatekey" > "$_conf"
        chmod 600 "$_dir"/*
        ln -s "$TUN/$TUN.conf" "$WG_DIR/$TUN.conf"
        _changed=1
    fi
    PSK=""

    if [ "$OPT_MON" -eq 1 ]; then
        _dd=1; valid_ip "$_h" && _dd=0
        _wd=1; [ "$KA" -eq 0 ] && _wd=0
        _mc=$(printf 'ENABLED=1\nHS_MAX=%s\nDDNS=%s\nWATCHDOG=%s\nBACKOFF=300' "$(hs_min_safe "$TUN")" "$_dd" "$_wd")
        if [ "$(cat "$_dir/monitor.conf" 2>/dev/null)" != "$_mc" ]; then
            printf '%s\n' "$_mc" > "$_dir/monitor.conf"; chmod 600 "$_dir/monitor.conf"; _changed=1
        fi
        agent_installed || { install_agent >&2 && _changed=1; }
    fi
    if [ "$OPT_UP" -eq 1 ] && ! tunnel_is_up "$TUN"; then
        rm -f "$_dir/.admin-down"
        wg-quick up "$TUN" >/dev/null 2>&1 || cli_die "Falha ao subir $TUN." 2
        _changed=1
    fi
    if [ "$OPT_BOOT" -eq 1 ] && [ "$(init_system)" = "systemd" ] && ! systemctl is-enabled --quiet "wg-quick@$TUN" 2>/dev/null; then
        systemctl enable "wg-quick@$TUN" >/dev/null 2>&1 && _changed=1
    fi

    if [ "$_changed" -eq 1 ]; then echo "STATUS=changed"; else echo "STATUS=unchanged"; fi
    echo "PUBKEY=$(tr -d ' \t\r\n' < "$_dir/publickey")"
}

cli_main() {
    ACTION=""; TUN=""; EP_ARG=""; SRV_PUB=""; ADDR_IN=""; ALLOWED_IN=""; SRV_TIP=""
    PSK_FILE=""; PSK_STDIN=0; DNS_IN=""; KA=25; MTU=""; OPT_UP=0; OPT_BOOT=0; OPT_MON=0; STRICT=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --create) ACTION=create ;;
            --name|--endpoint|--server-pubkey|--address|--allowed-ips|--server-tunnel-ip|--psk-file|--dns|--keepalive|--mtu|--show-pubkey|--diagnose)
                [ $# -ge 2 ] || cli_die "$1 requer um valor."
                case "$1" in
                    --name) TUN=$2 ;; --endpoint) EP_ARG=$2 ;; --server-pubkey) SRV_PUB=$2 ;;
                    --address) ADDR_IN=$2 ;; --allowed-ips) ALLOWED_IN=$2 ;; --server-tunnel-ip) SRV_TIP=$2 ;;
                    --psk-file) PSK_FILE=$2 ;; --dns) DNS_IN=$2 ;; --keepalive) KA=$2 ;; --mtu) MTU=$2 ;;
                    --show-pubkey) ACTION=pubkey; TUN=$2 ;; --diagnose) ACTION=diagnose; TUN=$2 ;;
                esac
                shift ;;
            --psk|--psk=*|--private-key*) cli_die "Segredo como argumento e proibido (fica visivel no ps/historico). Use --psk-file ou --psk-stdin." ;;
            --psk-stdin) PSK_STDIN=1 ;;
            --up) OPT_UP=1 ;; --boot) OPT_BOOT=1 ;; --monitor) OPT_MON=1 ;; --strict) STRICT=1 ;;
            --list) ACTION=list ;;
            --maintenance) ACTION=maint ;;
            --install) ACTION=install ;;
            --version) echo "wg-client-manager v$VERSION"; exit 0 ;;
            --help|-h) usage; exit 0 ;;
            *) cli_die "Opcao desconhecida: $1 (veja --help)" ;;
        esac
        shift
    done
    require_root
    case "$ACTION" in
        create)   wg_installed || cli_die "WireGuard nao instalado (use --install)." 2; cli_create ;;
        pubkey)   tunnel_exists "$TUN" || cli_die "Tunel '$TUN' nao encontrado."; tr -d ' \t\r\n' < "$WG_DIR/$TUN/publickey"; echo ;;
        list)     list_clients ;;
        diagnose) tunnel_exists "$TUN" || cli_die "Tunel '$TUN' nao encontrado."; diagnose_tunnel "$TUN" ;;
        maint)    wg_installed || exit 0; run_maintenance ;;
        install)  install_wg || exit 2 ;;
        *)        cli_die "Nenhuma acao informada (veja --help)." ;;
    esac
}

# ----------------------------------------------------------------------------
# Menu
# ----------------------------------------------------------------------------
header() {
    clear 2>/dev/null || printf '\033c'
    printf '=====================================================\n'
    printf ' WireGuard Client Manager v%s - EdenCore\n' "$VERSION"
    printf '=====================================================\n'
    if wg_installed; then
        printf ' Status: %sWireGuard instalado%s\n' "$C_G" "$C_N"
    else
        printf ' Status: %sWireGuard NAO instalado (use a opcao 2)%s\n' "$C_R" "$C_N"
    fi
    printf ' Instrutor: Daniel Selbach Figueiró\n'
    printf -- '-----------------------------------------------------\n'
    printf ' 1) Verificar instalacao do WireGuard\n'
    printf ' 2) Instalar WireGuard e dependencias\n'
    printf ' 3) Criar cliente WireGuard\n'
    printf ' 4) Listar clientes\n'
    printf ' 5) Exibir chave publica do cliente (cadastro no servidor)\n'
    printf ' 6) Ativar tunel (com teste de handshake)\n'
    printf ' 7) Desativar tunel\n'
    printf ' 8) Habilitar tunel no boot\n'
    printf ' 9) Status (wg show)\n'
    printf '10) Diagnostico de handshake\n'
    printf '11) Rotacionar par de chaves do cliente\n'
    printf '12) Atualizar PSK (gerada no servidor)\n'
    printf '13) Exibir configuracao (chaves ocultas)\n'
    printf '14) Debug / troubleshooting (log detalhado, MTU)\n'
    printf '15) Monitoramento automatico (DDNS + watchdog)\n'
    printf '16) Backups e rollback\n'
    printf '17) Remover cliente\n'
    printf ' 0) Sair\n'
    printf -- '-----------------------------------------------------\n'
}

need_wg() {
    wg_installed && return 0
    msg_err "WireGuard nao instalado. Use a opcao 2."
    return 1
}

main() {
    if [ $# -gt 0 ]; then
        cli_main "$@"
        exit $?
    fi
    require_root
    while :; do
        header
        ask OPT "Opcao"
        case "$OPT" in
            1) check_install ;;
            2) install_wg ;;
            3) create_client ;;
            4) list_clients ;;
            5) select_tunnel T && show_peer_info "$T" ;;
            6) need_wg && select_tunnel T && tunnel_up "$T" ;;
            7) need_wg && select_tunnel T && tunnel_down "$T" ;;
            8) need_wg && select_tunnel T && tunnel_boot "$T" ;;
            9) show_status ;;
           10) need_wg && select_tunnel T && diagnose_tunnel "$T" ;;
           11) need_wg && rotate_keys ;;
           12) need_wg && update_psk ;;
           13) show_conf_masked ;;
           14) debug_menu ;;
           15) monitor_menu ;;
           16) rollback_tunnel ;;
           17) need_wg && remove_client ;;
            0) exit 0 ;;
            *) msg_err "Opcao invalida." ;;
        esac
        pause
    done
}

main "$@"
