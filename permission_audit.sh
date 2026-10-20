#!/usr/bin/env bash
#
# modules/permission_audit.sh
# Modulo: Analise de permissoes de arquivos e diretorios sensiveis.
# Apenas leitura/testes de permissao. Nenhum arquivo e modificado ou criado
# fora do diretorio de saida de relatorios (gerenciado pelo script principal).
# Conteudo de arquivos sensiveis NUNCA e impresso ou incluido no relatorio.

module_permission_audit() {
  # --- PATH contendo diretorio gravavel por outros (vetor de hijacking de binario) ---
  local path_entry
  local path_issue_found=0
  IFS=':' read -ra _pcsec_path_parts <<< "${PATH:-}"
  for path_entry in "${_pcsec_path_parts[@]}"; do
    [ -z "$path_entry" ] && continue
    [ "$path_entry" = "." ] && {
      path_issue_found=1
      report_finding \
        "File Permission Analysis" \
        "PATH contem '.'" \
        "O diretorio atual (.) esta presente na variavel PATH." \
        "PATH=$PATH" \
        "HIGH" \
        "Incluir o diretorio atual no PATH pode levar a execucao acidental de binarios maliciosos colocados em diretorios de trabalho nao confiaveis." \
        "Remova '.' do PATH; execute binarios locais explicitamente com './'." \
        "Risco depende do usuario navegar e executar comandos em diretorios nao confiaveis." \
        "confirmed"
      continue
    }
    if [ -d "$path_entry" ] && [ -w "$path_entry" ] && [ "$(stat -c '%U' "$path_entry" 2>/dev/null)" != "$(id -un 2>/dev/null)" ]; then
      path_issue_found=1
      report_finding \
        "File Permission Analysis" \
        "$path_entry (PATH)" \
        "Diretorio presente no PATH e gravavel pelo usuario atual, mas pertence a outro usuario/owner." \
        "Teste de permissao: gravavel = sim | Dono: $(stat -c '%U' "$path_entry" 2>/dev/null)" \
        "HIGH" \
        "Se este diretorio aparece antes de diretorios de sistema no PATH, um binario malicioso com mesmo nome de um comando comum pode ser executado em vez do original (PATH hijacking)." \
        "Remova permissao de escrita de outros usuarios neste diretorio ou retire-o do PATH." \
        "A exploracao real depende da ordem do PATH e de qual binario e chamado primeiro." \
        "potential"
    fi
  done
  if [ "$path_issue_found" -eq 0 ]; then
    report_finding \
      "File Permission Analysis" \
      "Variavel PATH" \
      "Nenhum problema classico foi identificado na composicao da variavel PATH." \
      "PATH verificado quanto a '.' e diretorios graviaveis por terceiros" \
      "INFO" \
      "Resultado esperado em configuracoes padrao." \
      "Nenhuma acao necessaria." \
      "N/A" \
      "info"
  fi

  # --- Arquivos de configuracao sensiveis: apenas testa permissao, nunca le conteudo ---
  local sensitive_files=(
    "/etc/passwd" "/etc/shadow" "/etc/group" "/etc/gshadow"
    "/etc/ssh/sshd_config" "/root/.ssh/authorized_keys"
  )
  local sf
  for sf in "${sensitive_files[@]}"; do
    [ -e "$sf" ] || continue
    local perms owner
    perms="$(stat -c '%A' "$sf" 2>/dev/null)"
    owner="$(stat -c '%U' "$sf" 2>/dev/null)"
    if [ -w "$sf" ]; then
      report_finding \
        "File Permission Analysis" \
        "$sf" \
        "Arquivo sensivel do sistema e gravavel pelo usuario atual." \
        "Permissoes: $perms | Dono: $owner" \
        "CRITICAL" \
        "Escrita em arquivos como /etc/passwd ou /etc/shadow pode permitir a criacao de um usuario com privilegios de root ou alteracao de credenciais existentes." \
        "Corrija imediatamente as permissoes do arquivo (tipicamente 644 para passwd/group, 640/000 para shadow/gshadow, dono root)." \
        "Nenhuma alteracao foi feita neste arquivo por esta ferramenta; o conteudo tambem nao foi lido ou exibido." \
        "confirmed"
    elif [ "$sf" = "/etc/shadow" ] && [ -r "$sf" ] && [ "$(id -u 2>/dev/null)" != "0" ]; then
      report_finding \
        "File Permission Analysis" \
        "$sf" \
        "Arquivo /etc/shadow e legivel por um usuario sem privilegio root, o que nao e o comportamento padrao esperado." \
        "Permissoes: $perms | Dono: $owner (conteudo NAO foi lido por esta ferramenta)" \
        "HIGH" \
        "Leitura de hashes de senha pode permitir ataques offline de quebra de senha, possivelmente levando a escalacao de privilegios." \
        "Restrinja a permissao de leitura do arquivo apenas a root (ou ao grupo 'shadow' quando aplicavel)." \
        "A ferramenta verificou apenas a permissao do arquivo; nenhum conteudo foi acessado ou reportado." \
        "confirmed"
    fi
  done

  # --- Diretorios home com permissao excessiva ---
  if [ -d /home ]; then
    local home_dir
    while IFS= read -r home_dir; do
      [ -z "$home_dir" ] && continue
      local perms
      perms="$(stat -c '%a' "$home_dir" 2>/dev/null)"
      # Permissao de escrita para "outros" (ultimo digito contem bit de escrita: 2,3,6,7)
      case "$perms" in
        *2|*3|*6|*7)
          report_finding \
            "File Permission Analysis" \
            "$home_dir" \
            "Diretorio home com permissao de escrita para 'outros' usuarios." \
            "Permissoes octais: $perms" \
            "MEDIUM" \
            "Diretorios home graviaveis por qualquer usuario podem permitir manipulacao de arquivos de configuracao pessoal (ex. .bashrc, chaves SSH) de outra conta." \
            "Restrinja a permissao do diretorio home (tipicamente 750 ou 700)." \
            "Nao foi verificado o conteudo interno do diretorio, apenas a permissao do diretorio em si." \
            "potential"
          ;;
      esac
    done <<< "$(find /home -maxdepth 1 -mindepth 1 -type d 2>/dev/null)"
  fi

  # --- Arquivos de inicializacao do shell do usuario atual, graviaveis por outros ---
  local rc_file
  for rc_file in "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile" "$HOME/.zshrc"; do
    [ -f "$rc_file" ] || continue
    local perms
    perms="$(stat -c '%a' "$rc_file" 2>/dev/null)"
    case "$perms" in
      *2|*3|*6|*7)
        report_finding \
          "File Permission Analysis" \
          "$rc_file" \
          "Arquivo de inicializacao do shell do usuario atual e gravavel por outros usuarios." \
          "Permissoes octais: $perms" \
          "MEDIUM" \
          "Caso outro usuario consiga escrever neste arquivo, comandos arbitrarios podem ser executados na proxima vez que o usuario-alvo abrir um shell." \
          "Restrinja a permissao do arquivo para leitura/escrita apenas pelo proprietario (ex. 600 ou 644)." \
          "Risco depende de outro usuario de fato ter acesso de escrita e intencao maliciosa; apenas a permissao foi verificada." \
          "potential"
        ;;
    esac
  done
}
