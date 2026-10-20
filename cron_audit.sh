#!/usr/bin/env bash
#
# modules/cron_audit.sh
# Modulo: Auditoria de tarefas agendadas (cron).
# Apenas leitura. Nenhuma tarefa e criada, editada ou executada.

module_cron_audit() {
  # --- Crontab do usuario atual ---
  if has_cmd crontab; then
    local own_cron
    own_cron="$(crontab -l 2>/dev/null)"
    if [ -n "$own_cron" ]; then
      report_finding \
        "Scheduled Tasks (Cron) Audit" \
        "crontab do usuario atual" \
        "O usuario atual possui tarefas agendadas via crontab pessoal." \
        "Quantidade de linhas nao vazias/nao comentadas: $(echo "$own_cron" | grep -vc '^\s*#\|^\s*$')" \
        "INFO" \
        "Tarefas pessoais sao esperadas e nao representam risco por si so." \
        "Revise os comandos agendados quanto a caminhos inseguros ou scripts graviaveis por terceiros." \
        "Apenas a crontab do usuario atual foi lida; crontabs de outros usuarios nao sao acessiveis sem privilegio." \
        "info"
    else
      report_finding \
        "Scheduled Tasks (Cron) Audit" \
        "crontab do usuario atual" \
        "Nenhuma tarefa agendada encontrada na crontab pessoal do usuario atual." \
        "crontab -l -> vazio ou nao configurado" \
        "INFO" \
        "Resultado neutro; nao indica problema." \
        "Nenhuma acao necessaria." \
        "N/A" \
        "info"
    fi
  fi

  # --- Arquivos cron do sistema, apenas se legiveis ---
  local sys_cron_paths=("/etc/crontab")
  local p
  for p in "${sys_cron_paths[@]}"; do
    if [ -f "$p" ] && [ -r "$p" ]; then
      local perms owner
      perms="$(stat -c '%A' "$p" 2>/dev/null)"
      owner="$(stat -c '%U' "$p" 2>/dev/null)"
      if [ -w "$p" ]; then
        report_finding \
          "Scheduled Tasks (Cron) Audit" \
          "$p" \
          "Arquivo de cron do sistema e gravavel pelo usuario atual." \
          "Permissoes: $perms | Dono: $owner" \
          "CRITICAL" \
          "Escrita neste arquivo permite agendar comandos que normalmente serao executados como root, representando um caminho direto de escalacao de privilegios." \
          "Corrija as permissoes para que apenas root possa escrever neste arquivo (geralmente 644, dono root)." \
          "Nenhuma tarefa foi adicionada ou modificada por esta ferramenta." \
          "confirmed"
      else
        report_finding \
          "Scheduled Tasks (Cron) Audit" \
          "$p" \
          "Arquivo de cron do sistema e legivel; conteudo nao sera reproduzido no relatorio para evitar exposicao desnecessaria." \
          "Permissoes: $perms | Dono: $owner" \
          "INFO" \
          "Leitura isolada nao representa risco; o foco e a permissao de escrita, que esta corretamente restrita." \
          "Revise manualmente o conteudo apenas se necessario para a auditoria." \
          "Conteudo integral omitido deliberadamente." \
          "info"
      fi
    fi
  done

  # --- Diretorios cron.d / cron.daily etc, verificando permissao de escrita ---
  local cron_dirs=("/etc/cron.d" "/etc/cron.daily" "/etc/cron.hourly" "/etc/cron.weekly" "/etc/cron.monthly")
  local d
  for d in "${cron_dirs[@]}"; do
    [ -d "$d" ] || continue
    if [ -w "$d" ]; then
      report_finding \
        "Scheduled Tasks (Cron) Audit" \
        "$d" \
        "Diretorio de tarefas agendadas do sistema e gravavel pelo usuario atual." \
        "Teste de permissao: diretorio gravavel = sim" \
        "CRITICAL" \
        "Scripts colocados neste diretorio sao tipicamente executados pelo cron do sistema com privilegios de root." \
        "Corrija a permissao do diretorio imediatamente para restringir escrita apenas a root." \
        "Nenhum arquivo foi criado neste diretorio por esta ferramenta." \
        "confirmed"
    else
      # Verifica se algum script dentro do diretorio e gravavel por outros
      local f
      while IFS= read -r f; do
        [ -z "$f" ] && continue
        if [ -w "$f" ]; then
          report_finding \
            "Scheduled Tasks (Cron) Audit" \
            "$f" \
            "Script dentro de diretorio cron do sistema e gravavel pelo usuario atual." \
            "Teste de permissao: arquivo gravavel = sim" \
            "HIGH" \
            "Scripts executados periodicamente como root que podem ser sobrescritos representam um vetor pratico de escalacao de privilegios." \
            "Ajuste o proprietario/permissoes do script para impedir escrita por usuarios nao privilegiados." \
            "Nao foi verificado neste modulo se o script e de fato agendado ou apenas armazenado no diretorio." \
            "potential"
        fi
      done <<< "$(find "$d" -maxdepth 1 -type f 2>/dev/null)"
    fi
  done
}
