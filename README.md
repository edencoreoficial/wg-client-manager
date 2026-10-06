# wg-client-manager

Script em shell para criar, operar e diagnosticar clientes WireGuard em qualquer distribuição Linux, com menu interativo ou modo automatizado.

Projeto da **EdenCore**, comunidade de Infraestrutura de TI. 

Instrutor: **Daniel Selbach Figueiró**.

[![CI](https://github.com/edencoreoficial/wg-client-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/edencoreoficial/wg-client-manager/actions/workflows/ci.yml)

> **Transparência:** este script foi desenvolvido com auxílio de IA (Claude, da Anthropic). O código foi revisado, testado e validado pelo instrutor antes da publicação.

## O que ele faz

- Cria o cliente WireGuard com validação de todos os campos: nome do túnel, endpoint, porta, chaves, CIDRs, DNS, keepalive e MTU.
- Gera a chave privada localmente e nunca a exibe na tela.
- Organiza cada túnel em uma pasta própria dentro de `/etc/wireguard`, com permissões restritas.
- Entrega pronto o bloco de cadastro do peer no servidor, para wg-quick e para MikroTik RouterOS v7.
- Diagnostica falhas de handshake e aponta a causa provável.
- Monitora o túnel em segundo plano: corrige o endpoint quando o IP do servidor muda (DDNS) e reinicia o túnel quando ele trava (watchdog).
- Faz backup antes de qualquer alteração sensível e permite desfazer com um comando.

## Compatibilidade

| Item | Suporte |
|---|---|
| Shell | POSIX `sh`: bash, dash, ash/busybox |
| Gerenciadores de pacote | apt, dnf, yum, zypper, pacman, apk, xbps, emerge |
| Init | systemd e OpenRC (cron como alternativa ao timer) |
| Firewall local | Qualquer um (ufw, firewalld, nftables, iptables). O script apenas lê o estado e nunca altera regras |
| Kernel | 5.6 ou superior (módulo nativo). Anteriores exigem `wireguard-dkms` ou `wireguard-go` |

## Instalação

Baixe o script e o arquivo de verificação da [última release](https://github.com/edencoreoficial/wg-client-manager/releases/latest):

```bash
VER=v1.6.2
curl -fsSLO https://github.com/edencoreoficial/wg-client-manager/releases/download/$VER/wg-client-manager.sh
curl -fsSLO https://github.com/edencoreoficial/wg-client-manager/releases/download/$VER/wg-client-manager.sh.sha256
sha256sum -c wg-client-manager.sh.sha256
```

A saída precisa ser `wg-client-manager.sh: OK`. Se aparecer `FAILED`, **não execute**: o arquivo foi alterado ou corrompido no caminho.

Por que conferir: o script roda como root e mexe em rede. O SHA256 garante que o arquivo baixado é exatamente o que foi publicado.

## Uso interativo

```bash
sudo sh wg-client-manager.sh
```

Fluxo recomendado para o primeiro túnel:

1. **Opção 1** verifica o ambiente. **Opção 2** instala WireGuard e dependências, se faltar algo.
2. **Opção 3** cria o cliente. Tenha em mãos: IP ou hostname do servidor, porta, chave pública do servidor, IP do cliente no túnel, redes que devem passar pela VPN e a PSK (se o servidor usar).
3. Cadastre o peer no servidor com o bloco que o script exibe ao final. Depois confira no servidor com o comando `print detail` sugerido.
4. **Opção 6** sobe o túnel e já testa o handshake.
5. **Opção 15 → 1** ativa o monitoramento automático.

### Mapa do menu

| Opção | Função |
|---|---|
| 1-2 | Verificar ambiente e instalar dependências |
| 3-5 | Criar cliente, listar, exibir chave pública e bloco de cadastro |
| 6-9 | Ativar, desativar, habilitar no boot, status |
| 10 | Diagnóstico de handshake |
| 11-12 | Rotacionar par de chaves, atualizar PSK |
| 13 | Exibir configuração com chaves ocultas (para suporte) |
| 14 | Debug: captura guiada, log do kernel ao vivo, teste de MTU, retenção |
| 15 | Monitoramento automático: DDNS, watchdog, testes controlados |
| 16 | Backups e rollback |
| 17 | Remover cliente |

## Uso automatizado

Útil para Ansible, scripts de implantação ou provisionamento em lote. A execução é idempotente: repetir o mesmo comando não altera nada.

```bash
sudo sh wg-client-manager.sh --create --name wg-matriz \
  --endpoint vpn.exemplo.com.br:51820 \
  --server-pubkey <CHAVE_PUBLICA_DO_SERVIDOR> \
  --address 10.8.0.2/32 --server-tunnel-ip 10.8.0.1 \
  --allowed-ips "192.168.10.0/24,192.168.20.0/24" \
  --psk-file /root/psk-matriz.txt --keepalive 25 \
  --up --boot --monitor
```

Saída:

```
STATUS=changed
PUBKEY=<chave pública do cliente>
```

Na segunda execução com os mesmos parâmetros, a saída é `STATUS=unchanged`. Se algum parâmetro mudar, o script atualiza o `.conf`, mantém a chave privada existente e faz backup antes.

A PSK nunca é aceita como argumento, porque ficaria visível no `ps` e no histórico do shell. Use `--psk-file` ou `--psk-stdin`.

Exemplo de task Ansible:

```yaml
- name: Cliente WireGuard
  ansible.builtin.command: >
    sh /usr/local/src/wg-client-manager.sh --create --name wg-matriz
    --endpoint vpn.exemplo.com.br:51820 --server-pubkey {{ wg_server_pubkey }}
    --address 10.8.0.2/32 --allowed-ips 192.168.10.0/24
    --psk-file /root/psk-matriz.txt --up --boot --monitor
  register: wg
  changed_when: "'STATUS=changed' in wg.stdout"
```

Todas as opções: `sh wg-client-manager.sh --help`.

Códigos de saída: `0` sucesso, `1` entrada inválida, `2` erro de execução.

## Monitoramento automático

O agente roda a cada minuto (timer systemd ou cron) e age somente quando o handshake envelhece:

1. **DDNS:** resolve o hostname do servidor de novo. Se o IP mudou, atualiza o endpoint com `wg set`, sem derrubar a sessão.
2. **Watchdog:** se o IP é o mesmo e o handshake passou do limite, reinicia o túnel. O limite mínimo é calculado pelo keepalive (keepalive 25 ou 30 resulta em 180 s), e há intervalo mínimo de 5 minutos entre reinícios.

Túnel desligado pelo menu (opção 7) não é religado pelo watchdog.

Eventos ficam em `/var/log/wg-client-manager/maintenance.log` e no `journalctl -u wg-client-manager-maint`.

Para validar em produção, use os testes controlados (menu 15 → 7 e 15 → 8). Eles não mexem no firewall e desfazem tudo ao final, inclusive em Ctrl+C.

O agente é uma cópia do script em `/usr/local/sbin/wg-client-manager`. Depois de atualizar o script, reinstale pela opção 15 → 5.

## Troubleshooting

A opção 14 → 1 faz uma captura guiada e gera um relatório com análise automática em `/var/log/wg-client-manager/`. Nenhum log sai da máquina.

Casos reais que o diagnóstico identifica:

| Sintoma | Causa provável |
|---|---|
| Iniciações de handshake saem e nada volta | Chave pública do cliente ausente ou errada no peer do servidor, UDP bloqueado ou endpoint incorreto |
| Servidor responde mas o handshake não fecha | PSK divergente entre as pontas ou chave pública do servidor errada no cliente |
| Handshake OK, mas o IP do servidor no túnel não responde | Firewall de input/ICMP no servidor |
| Ping responde rápido demais (menos de 1 ms) para um IP do túnel | Sobreposição: a sub-rede do túnel existe na rede local |
| Ping funciona, SSH ou HTTPS trava | MTU acima do caminho. Use o teste de MTU (14 → 3) |

Regras que evitam a maioria dos problemas:

- No servidor, o `allowed-address` do peer deve conter apenas o /32 do cliente, nunca as LANs do próprio servidor.
- Depois de qualquer alteração no servidor, confira com `print detail` antes de testar no cliente.
- Nunca cole chave privada ou PSK em chat, e-mail ou chamado. Para suporte, use a opção 13, que oculta os segredos.

## Segurança por Design

- Executa somente como root, com `umask 077`: pastas 700 e arquivos 600.
- A chave privada é gerada localmente e nunca aparece na tela, em log ou em relatório.
- Segredos nunca passam como argumento de processo externo.
- Toda entrada é validada antes de ser gravada.
- Não altera firewall, `ip_forward` nem NAT do host.
- O debug do kernel é desligado automaticamente em qualquer saída do script.
- A remoção de túnel exige digitar o nome exato.

## Arquivos gerados

```
/etc/wireguard/<tunel>/privatekey        600
/etc/wireguard/<tunel>/publickey         600
/etc/wireguard/<tunel>/presharedkey      600 (se usada)
/etc/wireguard/<tunel>/<tunel>.conf      600
/etc/wireguard/<tunel>/monitor.conf      600 (se monitorado)
/etc/wireguard/<tunel>/.backup/          700 (5 backups mais recentes)
/etc/wireguard/<tunel>.conf              symlink para wg-quick e wg-quick@
/var/log/wg-client-manager/              700 (relatórios e maintenance.log)
/etc/wg-client-manager.conf              600 (retenção de relatórios)
/usr/local/sbin/wg-client-manager        700 (agente, se instalado)
```

## Contribuindo

Pull requests passam pelo CI automaticamente: ShellCheck, sintaxe em dash, bash e busybox, consistência de versão e teste de criação idempotente em Debian, Fedora, Alpine e Arch.

Antes de abrir um PR, rode localmente:

```bash
shellcheck -s sh wg-client-manager.sh
dash -n wg-client-manager.sh && bash -n wg-client-manager.sh
```

Registre a mudança no [CHANGELOG.md](CHANGELOG.md) e atualize a versão no cabeçalho e na variável `VERSION` do script.

## Licença

[MIT](LICENSE). Uso, cópia e modificação livres, inclusive comercial, mantendo o aviso de copyright.
