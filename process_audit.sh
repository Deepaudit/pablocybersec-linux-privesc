#!/usr/bin/env bash
#
# modules/process_audit.sh
# Modulo: Analise de processos e servicos (somente leitura).
# Nenhum processo e finalizado, iniciado ou reiniciado por esta ferramenta.

module_process_audit() {
  # --- Processos rodando como root, visiveis ao usuario atual ---
  if has_cmd ps; then
    local root_procs
    root_procs="$(ps -eo user,pid,comm 2>/dev/null | awk '$1=="root"{print $2, $3}' | head -n 50)"
    local root_count
    root_count="$(echo "$root_procs" | grep -c . 2>/dev/null || echo 0)"

    report_finding \
      "Process Audit" \
      "Processos em execucao como root" \
      "Contagem de processos visiveis ao usuario atual sendo executados com privilegio root." \
      "Quantidade observada (ate 50 listados): $root_count" \
      "INFO" \
      "Volume elevado de processos root e comum em servidores; nao representa falha por si so." \
      "Revise manualmente processos root inesperados ou associados a software desatualizado." \
      "Usuarios sem privilegios podem ter visibilidade limitada de todos os processos do sistema (depende de hidepid e afins)." \
      "info"
  else
    report_finding \
      "Process Audit" \
      "ps (binario)" \
      "Comando 'ps' indisponivel; listagem de processos pulada." \
      "command -v ps -> nao encontrado" \
      "INFO" \
      "Sem 'ps', a enumeracao de processos nao pode ser realizada neste ambiente." \
      "Garanta a presenca de procps/coreutils no sistema auditado." \
      "Nenhum dado coletado." \
      "info"
  fi

  # --- Executaveis de processos com caminho gravavel pelo usuario atual ---
  if has_cmd ps; then
    local writable_found=0
    local line pid exe
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      pid="$(echo "$line" | awk '{print $1}')"
      [ -z "$pid" ] && continue
      if [ -r "/proc/$pid/exe" ] 2>/dev/null; then
        exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null)"
        [ -z "$exe" ] && continue
        if [ -w "$exe" ] 2>/dev/null; then
          writable_found=1
          report_finding \
            "Process Audit" \
            "$exe (pid $pid)" \
            "O binario em execucao referenciado por este processo e gravavel pelo usuario atual." \
            "/proc/$pid/exe -> $exe (gravavel: sim)" \
            "HIGH" \
            "Se o processo roda com privilegios mais altos que o usuario atual e o binario pode ser sobrescrito, ha um possivel caminho para execucao de codigo com privilegio elevado na proxima execucao do servico." \
            "Restrinja a permissao de escrita do binario (chown/chmod apropriados) ou mova-o para um diretorio protegido." \
            "Nao foi verificado neste modulo se o processo roda com UID diferente do usuario atual; valide manualmente o proprietario do processo antes de concluir exploracao." \
            "potential"
        fi
      fi
    done <<< "$(ps -eo pid= 2>/dev/null)"

    if [ "$writable_found" -eq 0 ]; then
      report_finding \
        "Process Audit" \
        "Binarios de processos em execucao" \
        "Nenhum binario de processo acessivel foi identificado como gravavel pelo usuario atual." \
        "Verificacao realizada via /proc/<pid>/exe para processos visiveis" \
        "INFO" \
        "Resultado esperado em sistemas com permissoes de arquivo bem configuradas." \
        "Nenhuma acao necessaria." \
        "Apenas processos visiveis e com /proc/<pid>/exe acessivel foram avaliados." \
        "info"
    fi
  fi

  # --- Servicos systemd ativos como root (quando systemctl disponivel) ---
  if has_cmd systemctl; then
    local svc_count
    svc_count="$(systemctl list-units --type=service --state=running 2>/dev/null | grep -c '\.service' 2>/dev/null || echo 0)"
    report_finding \
      "Service Configuration Audit" \
      "systemd - servicos em execucao" \
      "Quantidade de servicos systemd atualmente em execucao, visivel ao usuario atual." \
      "Servicos em execucao detectados: $svc_count" \
      "INFO" \
      "Informacao de contexto para correlacionar com achados de permissao de arquivos de unidade." \
      "Revise unit files (/etc/systemd/system/*.service) quanto a permissao de escrita indevida." \
      "A listagem completa pode exigir privilegios adicionais para detalhamento de cada unidade." \
      "info"

    # Verifica permissao de escrita em diretorios de unit files comuns
    local unit_dir
    for unit_dir in /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system; do
      if [ -d "$unit_dir" ] && [ -w "$unit_dir" ]; then
        report_finding \
          "Service Configuration Audit" \
          "$unit_dir" \
          "Diretorio de unidades systemd e gravavel pelo usuario atual." \
          "Teste de permissao: diretorio gravavel = sim" \
          "CRITICAL" \
          "Se o usuario pode criar ou modificar unit files neste diretorio, pode ser possivel definir um servico que execute comandos arbitrarios na proxima vez que for iniciado por root (ex. via systemctl daemon-reload + start, sujeito a outras permissoes)." \
          "Corrija as permissoes do diretorio para que apenas root possa escrever nele." \
          "A exploracao efetiva depende de permissao adicional para iniciar/recarregar servicos, nao verificada automaticamente por esta ferramenta." \
          "confirmed"
      fi
    done
  else
    report_finding \
      "Service Configuration Audit" \
      "systemctl (binario)" \
      "systemctl nao encontrado; este sistema pode nao usar systemd ou a ferramenta esta ausente do PATH." \
      "command -v systemctl -> nao encontrado" \
      "INFO" \
      "Sistemas init alternativos (sysvinit, OpenRC, runit) nao sao verificados por este modulo." \
      "Nenhuma acao necessaria caso o sistema nao utilize systemd." \
      "Cobertura de outros sistemas de init nao implementada nesta versao." \
      "info"
  fi
}
