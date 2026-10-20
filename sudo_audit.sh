#!/usr/bin/env bash
#
# modules/sudo_audit.sh
# Modulo: Auditoria de configuracoes sudo.
#
# Regras do projeto:
#   - Nunca solicitar ou armazenar senha.
#   - Nunca executar comandos privilegiados encontrados.
#   - Apenas interpretar saida de "sudo -l" quando o proprio usuario
#     ja possui permissao de executa-lo sem prompt interativo (-n).

# Lista de padroes classicamente perigosos em regras sudo (base GTFOBins-like,
# apenas para classificacao, sem qualquer execucao).
_PCSEC_RISKY_SUDO_BINS=(
  "ALL" "vim" "vi" "nano" "less" "more" "man" "awk" "perl" "python" "python3"
  "ruby" "find" "bash" "sh" "dash" "zsh" "nmap" "tar" "zip" "unzip" "rsync"
  "docker" "systemctl" "service" "env" "pip" "pip3" "gdb" "ftp" "git" "scp"
  "node" "lua" "ld.so" "chmod" "chown" "cp" "mv" "dd"
)

_pcsec_sudo_line_is_risky() {
  local line="$1"
  local bin
  for bin in "${_PCSEC_RISKY_SUDO_BINS[@]}"; do
    if echo "$line" | grep -qiE "(^|[[:space:]/])${bin}([[:space:]]|$)"; then
      return 0
    fi
  done
  return 1
}

module_sudo_audit() {
  if ! has_cmd sudo; then
    report_finding \
      "Sudo Configuration Audit" \
      "sudo (binario)" \
      "O binario 'sudo' nao foi encontrado no PATH do sistema." \
      "command -v sudo -> nao encontrado" \
      "INFO" \
      "Sem sudo instalado, este vetor de escalacao especifico nao se aplica." \
      "Nenhuma acao necessaria." \
      "Pode existir em outro caminho fora do PATH atual." \
      "info"
    return 0
  fi

  # Tenta apenas o modo nao interativo (-n): nunca solicita senha.
  local sudo_out
  sudo_out="$(sudo -n -l 2>/dev/null)"
  local rc=$?

  if [ $rc -ne 0 ] || [ -z "$sudo_out" ]; then
    report_finding \
      "Sudo Configuration Audit" \
      "sudo -l (modo nao interativo)" \
      "Nao foi possivel listar as regras sudo do usuario atual sem senha interativa." \
      "sudo -n -l retornou codigo $rc ou saida vazia" \
      "INFO" \
      "O usuario pode nao ter permissao sudo, ou o sistema exige senha (comportamento esperado)." \
      "Se desejar validar manualmente, execute 'sudo -l' interativamente fora desta ferramenta." \
      "Esta ferramenta nunca solicita ou envia senhas; por isso a verificacao fica limitada ao modo nao interativo." \
      "info"
    return 0
  fi

  report_finding \
    "Sudo Configuration Audit" \
    "sudo -l (regras do usuario atual)" \
    "Regras sudo visiveis para o usuario atual sem necessidade de senha adicional." \
    "$(echo "$sudo_out" | tr '\n' ' ' | cut -c1-500)" \
    "LOW" \
    "A simples listagem de regras e informativa; o risco real depende dos binarios liberados." \
    "Revise manualmente cada regra listada e compare com o principio de menor privilegio." \
    "Saida pode estar truncada para 500 caracteres no relatorio resumido." \
    "info"

  # Analisa linha a linha em busca de padroes de alto risco (sem executar nada)
  local found_risky=0
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    if echo "$line" | grep -q "NOPASSWD" && _pcsec_sudo_line_is_risky "$line"; then
      found_risky=1
      report_finding \
        "Sudo Configuration Audit" \
        "Regra sudo: $(echo "$line" | cut -c1-200)" \
        "Regra sudo permite executar um binario potencialmente perigoso sem senha (NOPASSWD)." \
        "$(echo "$line" | cut -c1-300)" \
        "HIGH" \
        "Binarios como interpretadores, editores ou ferramentas de arquivo frequentemente permitem obter um shell com privilegios elevados (padrao documentado publicamente, ex. GTFOBins)." \
        "Restrinja a regra sudo ao comando minimo necessario, remova NOPASSWD ou utilize wrappers que limitem a funcionalidade." \
        "Esta ferramenta nao tenta explorar a regra; a exploracao real depende de validacao manual e autorizacao formal." \
        "potential"
    elif _pcsec_sudo_line_is_risky "$line"; then
      report_finding \
        "Sudo Configuration Audit" \
        "Regra sudo: $(echo "$line" | cut -c1-200)" \
        "Regra sudo permite executar um binario potencialmente perigoso (requer senha)." \
        "$(echo "$line" | cut -c1-300)" \
        "MEDIUM" \
        "O binario esta associado a tecnicas conhecidas de escalacao via sudo, mas a exigencia de senha reduz o risco imediato." \
        "Avalie se o binario realmente precisa de acesso sudo e restrinja argumentos quando possivel." \
        "Classificacao baseada em nome de binario; falsos positivos podem ocorrer conforme o contexto da regra." \
        "potential"
    fi
  done <<< "$sudo_out"

  if [ "$found_risky" -eq 0 ]; then
    report_finding \
      "Sudo Configuration Audit" \
      "Padroes de risco em regras sudo" \
      "Nenhum padrao classico de binario de alto risco foi identificado nas regras visiveis." \
      "Nenhuma correspondencia com a lista de binarios de referencia utilizada" \
      "INFO" \
      "Ausencia de padroes conhecidos reduz a probabilidade de escalacao trivial via sudo, mas nao a elimina." \
      "Revise periodicamente o arquivo /etc/sudoers e /etc/sudoers.d/ (quando legivel) com uma ferramenta dedicada de lint." \
      "A lista de binarios de referencia nao e exaustiva." \
      "info"
  fi

  # Verifica leitura de /etc/sudoers.d/ quando permitido (sem exibir conteudo integral)
  if [ -d /etc/sudoers.d ] && [ -r /etc/sudoers.d ]; then
    local count
    count="$(find /etc/sudoers.d -maxdepth 1 -type f 2>/dev/null | wc -l | tr -d ' ')"
    report_finding \
      "Sudo Configuration Audit" \
      "/etc/sudoers.d/" \
      "Diretorio de regras adicionais de sudo e listavel pelo usuario atual." \
      "Quantidade de arquivos encontrados: $count" \
      "INFO" \
      "A listagem do diretorio nao implica necessariamente leitura do conteudo dos arquivos." \
      "Garanta que apenas root possa ler/escrever nestes arquivos (permissao recomendada 440, dono root)." \
      "O conteudo dos arquivos so e inspecionado quando o usuario atual tem permissao de leitura neles." \
      "info"
  fi
}
