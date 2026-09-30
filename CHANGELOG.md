# Changelog

Todas as mudanças relevantes deste projeto ficam registradas aqui.
Formato baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e versionamento [SemVer](https://semver.org/lang/pt-BR/).

## [1.6.2] - 2026-09-29

### Corrigido
- Status do monitoramento mostra a próxima execução do timer. Timers com gatilho relativo (`OnBootSec`/`OnUnitActiveSec`) não preenchem `NextElapseUSecRealtime`; o valor passa a ser lido do `systemctl list-timers`.

### Alterado
- Histórico de versões movido do cabeçalho do script para este arquivo.

## [1.6.1] - 2026-09-29

### Corrigido
- Limite mínimo do watchdog calculado pelo keepalive do túnel: 120 s de rekey + keepalive + 30 s de margem (keepalive 30 resulta em 180 s). O mínimo fixo anterior (150 s) permitia reinício falso de túnel saudável.

### Adicionado
- Status alerta túneis monitorados com limite abaixo do seguro.

## [1.6.0] - 2026-09-29

### Adicionado
- Detecção do firewall local em modo somente leitura (ufw, firewalld, iptables-nft, iptables-legacy, nftables), exibida na verificação de ambiente e no relatório de debug.
- Teste controlado de DDNS: endpoint temporário em IP de documentação (RFC 5737/3849), com detecção de roaming nativo do WireGuard.
- Teste controlado de watchdog: rota blackhole temporária via iproute2, independente do firewall em uso.
- Limpeza garantida dos testes (rota e endpoint originais) ao fim, em erro ou Ctrl+C.

### Segurança
- O script nunca cria, altera ou remove regras de firewall.

## [1.5.1] - 2026-09-29

### Adicionado
- Trilha de auditoria no `maintenance.log`: instalação e remoção do agente, ativação e desativação de monitoramento. O arquivo existe desde a instalação, mesmo sem incidentes.

## [1.5.0] - 2026-09-29

### Adicionado
- Agente de manutenção (timer systemd ou cron) com re-resolução de endpoint DDNS via `wg set`, sem derrubar a sessão.
- Watchdog de handshake com backoff de 5 minutos e respeito a desligamento administrativo.
- Backup datado antes de rotação de chaves, troca de PSK, gravação de MTU e atualização via CLI; rollback reversível.
- Teste de MTU até o endpoint com bit DF, sugestão e aplicação com backup.
- Modo não interativo idempotente (`--create`) com saída `STATUS=changed|unchanged` para Ansible.
- Retenção configurável de relatórios de debug.

### Segurança
- Segredos recusados como argumento de linha de comando (`--psk`); uso obrigatório de `--psk-file` ou `--psk-stdin`.

## [1.4.1] - 2026-09-29

### Adicionado
- Destino dos logs sempre informado na tela; gravação opcional do modo ao vivo; listagem e exibição de relatórios salvos.

## [1.4.0] - 2026-09-29

### Adicionado
- Módulo de debug: dynamic debug do módulo WireGuard do kernel, captura guiada com tcpdump, amostras de handshake, rotas, MTU e análise automática.
- Acompanhamento do log do kernel ao vivo. Debug sempre desligado ao sair do script.

## [1.3.0] - 2026-09-29

### Adicionado
- IP do servidor dentro do túnel incluído como /32 no AllowedIPs.
- Detecção de sobreposição do túnel com a rede local.
- Diagnóstico de handshake após subir o túnel.
- Rotação do par de chaves com comando `set` pronto para o servidor MikroTik.
- Atualização de PSK sem expor o segredo.
- Exibição do `.conf` com chaves ocultas, para suporte.

### Corrigido
- Remoção de duplicados no AllowedIPs.

## [1.2.1] - 2026-09-29

### Corrigido
- Chave pública exibida sem código de cor ANSI (cópia limpa para o servidor).
- Listagem sem quebra de coluna com endpoints longos.

### Adicionado
- Checagem de integridade entre chave privada e chave pública.

## [1.2.0] - 2026-09-29

### Adicionado
- Opção de menu para exibir a chave pública do cliente e o bloco de cadastro do peer no servidor (wg-quick e RouterOS v7).

## [1.1.0] - 2026-09-29

### Alterado
- PSK passa a ser apenas informada, pois é gerada no servidor.

## [1.0.0] - 2026-09-29

### Adicionado
- Versão inicial: menu interativo, instalação multi-distro, criação de cliente com validação estrita de entrada e pasta por túnel em `/etc/wireguard`.

[1.6.2]: https://github.com/edencoreoficial/wg-client-manager/releases/tag/v1.6.2
