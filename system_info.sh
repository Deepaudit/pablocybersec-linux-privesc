#!/usr/bin/env bash
#
# modules/system_info.sh
# Modulo: Enumeracao basica do sistema.
# Apenas leitura. Nenhuma alteracao ou execucao privilegiada e realizada.
#
# Depende das funcoes definidas em pcsec-privesc.sh (report_finding, has_cmd, etc.)

module_system_info() {
  local distro="desconhecida"
  local kernel arch user uid groups_list uptime_info hostname_info env_hint

  if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    distro="$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-${NAME:-desconhecida} ${VERSION:-}}")"
  elif has_cmd lsb_release; then
    distro="$(lsb_release -d 2>/dev/null | cut -f2-)"
  fi

  kernel="$(uname -r 2>/dev/null || echo desconhecido)"
  arch="$(uname -m 2>/dev/null || echo desconhecida)"
  user="$(id -un 2>/dev/null || echo desconhecido)"
  uid="$(id -u 2>/dev/null || echo "?")"
  groups_list="$(id -Gn 2>/dev/null || echo desconhecido)"
  hostname_info="$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || echo desconhecido)"

  if has_cmd uptime; then
    uptime_info="$(uptime -p 2>/dev/null || uptime 2>/dev/null)"
  else
    uptime_info="indisponivel (comando uptime ausente)"
  fi

  # Deteccao leve de ambiente de execucao (container / virtualizacao), sem
  # concluir nada alem do que e diretamente observavel.
  env_hint="host fisico ou nao identificado"
  if [ -f /.dockerenv ]; then
    env_hint="indicios de execucao em container Docker (/.dockerenv presente)"
  elif has_cmd systemd-detect-virt; then
    local v
    v="$(systemd-detect-virt 2>/dev/null)"
    [ -n "$v" ] && [ "$v" != "none" ] && env_hint="indicios de virtualizacao/container: $v"
  elif grep -qi 'docker\|kubepods\|lxc' /proc/1/cgroup 2>/dev/null; then
    env_hint="indicios de execucao em container (cgroup de PID 1)"
  fi

  report_finding \
    "System Enumeration" \
    "$hostname_info" \
    "Coleta de informacoes basicas do sistema para contextualizar a auditoria." \
    "Distro: $distro | Kernel: $kernel | Arch: $arch | Usuario: $user (uid=$uid) | Grupos: $groups_list | Uptime: $uptime_info | Ambiente: $env_hint" \
    "INFO" \
    "Informacao de contexto, nao representa uma vulnerabilidade por si so." \
    "Nenhuma acao necessaria. Utilize estes dados para correlacionar outros achados." \
    "Deteccao de ambiente (container/VM) e heuristica e pode nao identificar todos os casos." \
    "info"

  _pcsec_environment_checks
}

# -----------------------------------------------------------------------------
# Verificacoes adicionais de ambiente (item "I" do escopo do projeto):
# variaveis de ambiente relevantes, ferramentas administrativas disponiveis
# e indicios de containers. Mantido dentro deste modulo para preservar a
# estrutura de arquivos solicitada. Segredos encontrados sao sempre redigidos.
# -----------------------------------------------------------------------------
_pcsec_environment_checks() {
  # Variaveis de ambiente potencialmente sensiveis: reporta apenas a PRESENCA
  # da variavel, nunca o valor completo (redigido quando necessario citar algo).
  local sensitive_vars=("AWS_SECRET_ACCESS_KEY" "AWS_SESSION_TOKEN" "API_KEY" "TOKEN" "PASSWORD" "SECRET" "PRIVATE_KEY")
  local var_name found_any=0
  for var_name in "${sensitive_vars[@]}"; do
    if [ -n "${!var_name:-}" ]; then
      found_any=1
      report_finding \
        "Environment Configuration" \
        "Variavel de ambiente: $var_name" \
        "Uma variavel de ambiente com nome sugestivo de credencial esta definida no processo atual." \
        "Variavel presente; valor redigido: $(redact_secret "${!var_name}")" \
        "MEDIUM" \
        "Variaveis de ambiente podem ser herdadas por processos filhos e, dependendo da configuracao, ficar visiveis a outros usuarios via /proc/<pid>/environ." \
        "Evite armazenar segredos em variaveis de ambiente persistentes; prefira cofres de segredos dedicados (vault, secret manager)." \
        "O valor real nunca e exibido por esta ferramenta, apenas a presenca da variavel." \
        "potential"
    fi
  done
  if [ "$found_any" -eq 0 ]; then
    report_finding \
      "Environment Configuration" \
      "Variaveis de ambiente sensiveis" \
      "Nenhuma variavel de ambiente com nome sugestivo de credencial foi encontrada no processo atual." \
      "Lista de nomes de referencia verificada; nenhuma correspondencia" \
      "INFO" \
      "Resultado esperado em ambientes bem configurados." \
      "Nenhuma acao necessaria." \
      "Apenas variaveis do processo atual foram verificadas; outras sessoes nao foram inspecionadas." \
      "info"
  fi

  # Ferramentas administrativas disponiveis (apenas listagem informativa)
  local admin_tools=("docker" "kubectl" "lxc" "vagrant" "ansible" "terraform")
  local tool available=()
  for tool in "${admin_tools[@]}"; do
    has_cmd "$tool" && available+=("$tool")
  done
  if [ "${#available[@]}" -gt 0 ]; then
    report_finding \
      "Environment Configuration" \
      "Ferramentas administrativas disponiveis" \
      "Ferramentas de administracao/orquestracao detectadas no PATH do usuario atual." \
      "Ferramentas: ${available[*]}" \
      "INFO" \
      "A presenca dessas ferramentas pode indicar superficies adicionais relevantes (ex. grupo 'docker' equivalente a root efetivo)." \
      "Se o usuario pertence ao grupo 'docker' (ou similar), avalie esse acesso como equivalente a privilegios administrativos." \
      "Esta ferramenta nao verifica automaticamente a associacao a grupos privilegiados especificos de cada ferramenta listada." \
      "info"
  fi

  # Indicio adicional de container: cgroups e namespaces (apenas leitura)
  if [ -f /proc/1/sched ] && grep -q "init\|systemd" /proc/1/sched 2>/dev/null; then
    : # host tradicional, nenhum achado adicional necessario
  fi
}
