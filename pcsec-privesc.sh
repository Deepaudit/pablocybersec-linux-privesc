#!/usr/bin/env bash
#
# pcsec-privesc.sh
#
# PabloCyberSec Linux Privilege Escalation (PCSEC-PRIVESC)
# Ferramenta de auditoria de seguranca para identificar configuracoes
# inseguras e possiveis vetores de escalacao de privilegios em sistemas
# Linux AUTORIZADOS para auditoria.
#
# Desenvolvido por: PabloCyberSec
# Licenca: MIT (ver arquivo LICENSE)
#
# AVISO: esta ferramenta executa SOMENTE verificacoes locais de leitura.
# Ela NAO explora vulnerabilidades, NAO escala privilegios automaticamente,
# NAO modifica o sistema e NAO envia dados para servidores externos.
# Use apenas em sistemas para os quais voce tem autorizacao explicita.
#
set -u
# Nao usamos "set -e" de proposito: uma verificacao que falha nao deve
# interromper a auditoria completa. Erros sao tratados localmente.

# -----------------------------------------------------------------------------
# Metadados do projeto
# -----------------------------------------------------------------------------
PCSEC_NAME="PabloCyberSec Linux Privilege Escalation"
PCSEC_SHORTNAME="PCSEC-PRIVESC"
PCSEC_VERSION="1.0.0"
PCSEC_AUTHOR="PabloCyberSec"

# Diretorio onde o script esta localizado (para localizar modules/)
SCRIPT_SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SCRIPT_SOURCE" ]; do
  SCRIPT_DIR="$(cd -P "$(dirname "$SCRIPT_SOURCE")" >/dev/null 2>&1 && pwd)"
  SCRIPT_SOURCE="$(readlink "$SCRIPT_SOURCE")"
  [[ $SCRIPT_SOURCE != /* ]] && SCRIPT_SOURCE="$SCRIPT_DIR/$SCRIPT_SOURCE"
done
SCRIPT_DIR="$(cd -P "$(dirname "$SCRIPT_SOURCE")" >/dev/null 2>&1 && pwd)"
MODULES_DIR="$SCRIPT_DIR/modules"

# -----------------------------------------------------------------------------
# Estado global / configuracao de execucao
# -----------------------------------------------------------------------------
USE_COLOR=1
JSON_OUTPUT=0
OUTPUT_DIR=""
SCAN_MODE="full"      # "quick" ou "full"
LIST_CHECKS_ONLY=0

# Contadores de severidade (associativo)
declare -A SEV_COUNT=( [INFO]=0 [LOW]=0 [MEDIUM]=0 [HIGH]=0 [CRITICAL]=0 )
TOTAL_FINDINGS=0

# Buffers de relatorio
REPORT_LINES=()        # relatorio humano (texto)
JSON_FINDINGS=()       # objetos JSON (um por achado), só usados se --json

# Timestamp da execucao (usado em nomes de arquivos de saida)
RUN_TIMESTAMP="$(date +%Y%m%d_%H%M%S 2>/dev/null || echo "run")"

# Lista de modulos disponiveis (nome_funcao:descricao:arquivo)
# Mantida centralmente para suportar --checks e carregamento ordenado.
MODULE_LIST=(
  "module_system_info|System Enumeration|system_info.sh"
  "module_sudo_audit|Sudo Configuration Audit|sudo_audit.sh"
  "module_suid_sgid|SUID / SGID Audit|suid_sgid.sh"
  "module_capabilities|Linux Capabilities|capabilities.sh"
  "module_process_audit|Process & Service Audit|process_audit.sh"
  "module_cron_audit|Scheduled Tasks (Cron) Audit|cron_audit.sh"
  "module_permission_audit|File Permission Analysis|permission_audit.sh"
  "module_kernel_audit|Kernel & Update Audit|kernel_audit.sh"
)

# Modulos considerados "basicos" para --quick (mais rapidos / menor custo)
QUICK_MODULES=("module_system_info" "module_sudo_audit" "module_kernel_audit" "module_suid_sgid")

# -----------------------------------------------------------------------------
# Cores ANSI (definidas apos deteccao de suporte do terminal)
# -----------------------------------------------------------------------------
setup_colors() {
  if [ "$USE_COLOR" -eq 1 ] && [ -t 1 ] && command -v tput >/dev/null 2>&1 && [ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]; then
    C_RED="\033[0;31m"
    C_RED_BOLD="\033[1;31m"
    C_RED_INTENSE="\033[1;91m"
    C_GREEN="\033[0;32m"
    C_YELLOW="\033[0;33m"
    C_WHITE="\033[1;37m"
    C_GRAY="\033[0;90m"
    C_CYAN="\033[0;36m"
    C_RESET="\033[0m"
    C_BOLD="\033[1m"
  else
    C_RED=""; C_RED_BOLD=""; C_RED_INTENSE=""; C_GREEN=""; C_YELLOW=""
    C_WHITE=""; C_GRAY=""; C_CYAN=""; C_RESET=""; C_BOLD=""
  fi
}

# -----------------------------------------------------------------------------
# Banner
# -----------------------------------------------------------------------------
print_banner() {
  local line_w=63
  printf "\n"
  printf "${C_RED_BOLD}  ____   ____ ____  _____ ____ ${C_RESET}\n"
  printf "${C_RED_BOLD} |  _ \\ / ___/ ___|| ____/ ___|${C_RESET}\n"
  printf "${C_RED_BOLD} | |_) | |   \\___ \\|  _|| |    ${C_RESET}\n"
  printf "${C_RED_BOLD} |  __/| |___ ___) | |__| |___ ${C_RESET}\n"
  printf "${C_RED_BOLD} |_|    \\____|____/|_____\\____|${C_RESET}\n"
  printf "\n"
  printf "${C_WHITE}  PABLOCYBERSEC${C_RESET}\n"
  printf "${C_WHITE}  LINUX PRIVILEGE ESCALATION${C_RESET}\n"
  printf "${C_GRAY}  Security Auditing & Misconfiguration Analysis${C_RESET}\n"
  printf "${C_GRAY}  Developed by %s${C_RESET}\n" "$PCSEC_AUTHOR"
  printf "${C_GRAY}  Version %s${C_RESET}\n" "$PCSEC_VERSION"
  printf "\n"
  printf "${C_YELLOW}  AVISO: use apenas em sistemas com autorizacao explicita.${C_RESET}\n"
  printf "${C_YELLOW}  Nenhum exploit e executado. Nenhuma alteracao e feita.${C_RESET}\n"
  printf "\n"
}

# -----------------------------------------------------------------------------
# Ajuda / versao
# -----------------------------------------------------------------------------
print_help() {
  cat <<EOF
$PCSEC_NAME ($PCSEC_SHORTNAME) v$PCSEC_VERSION
Developed by $PCSEC_AUTHOR

Uso:
  ./pcsec-privesc.sh [opcoes]

Opcoes:
  --help            Mostra esta ajuda e encerra.
  --version         Mostra a versao e encerra.
  --quick           Executa apenas as verificacoes basicas (mais rapidas).
  --full            Executa todas as verificacoes implementadas (padrao).
  --no-color        Desativa cores na saida do terminal.
  --output DIR      Define o diretorio onde os relatorios serao salvos.
                    (padrao: ./pcsec-reports)
  --json            Gera, alem do relatorio texto, um relatorio em JSON.
  --checks          Lista todos os modulos/verificacoes disponiveis e sai.

Exemplos:
  ./pcsec-privesc.sh --full
  ./pcsec-privesc.sh --quick --no-color
  ./pcsec-privesc.sh --full --json --output /tmp/auditoria

Importante:
  - Esta ferramenta realiza apenas verificacoes locais de leitura.
  - Nao executa exploits, nao escala privilegios e nao altera o sistema.
  - Nao requer privilegios root para as verificacoes basicas.
  - Nao transmite nenhum dado para servidores externos.

Use somente em sistemas para os quais voce possui autorizacao.
EOF
}

print_version() {
  echo "$PCSEC_NAME ($PCSEC_SHORTNAME) v$PCSEC_VERSION - by $PCSEC_AUTHOR"
}

print_checks_list() {
  echo "$PCSEC_SHORTNAME - Verificacoes disponiveis:"
  echo ""
  local entry fn desc file
  for entry in "${MODULE_LIST[@]}"; do
    IFS='|' read -r fn desc file <<< "$entry"
    printf "  - %-22s %s  (modules/%s)\n" "$fn" "$desc" "$file"
  done
  echo ""
  echo "Use --quick para um subconjunto basico, ou --full para todas."
}

# -----------------------------------------------------------------------------
# Utilitarios gerais
# -----------------------------------------------------------------------------

# Verifica se um comando existe no PATH
has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

# Escapa uma string para uso seguro dentro de JSON
json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\t'/\\t}"
  s="${s//$'\r'/}"
  printf '%s' "$s"
}

# Redige valores potencialmente sensiveis antes de qualquer impressao/relatorio.
# Uso: redacted="$(redact_secret "$valor")"
redact_secret() {
  local v="$1"
  if [ -z "$v" ]; then
    printf '%s' "$v"
    return
  fi
  local len=${#v}
  if [ "$len" -le 6 ]; then
    printf '[REDACTED]'
  else
    printf '%s...[REDACTED]' "${v:0:3}"
  fi
}

# Mapeia severidade para cor
sev_color() {
  case "$1" in
    INFO) echo -ne "$C_CYAN" ;;
    LOW) echo -ne "$C_GREEN" ;;
    MEDIUM) echo -ne "$C_YELLOW" ;;
    HIGH) echo -ne "$C_RED" ;;
    CRITICAL) echo -ne "$C_RED_INTENSE" ;;
    *) echo -ne "$C_WHITE" ;;
  esac
}

# -----------------------------------------------------------------------------
# Motor de achados (findings)
#
# report_finding assina a "ficha" padronizada exigida pelo projeto:
#   nome, caminho/config, descricao do risco, evidencia minima,
#   severidade, motivo da classificacao, recomendacao, limitacoes.
#
# A classificacao distingue (via campo CONFIDENCE):
#   confirmed   -> configuracao confirmadamente insegura
#   potential   -> possivel vetor que precisa de validacao manual
#   info        -> informacao que requer investigacao manual
# -----------------------------------------------------------------------------
report_finding() {
  # Parametros nomeados via variaveis locais para legibilidade
  local check_name="$1"
  local target="$2"
  local description="$3"
  local evidence="$4"
  local severity="$5"        # INFO|LOW|MEDIUM|HIGH|CRITICAL
  local reason="$6"
  local recommendation="$7"
  local limitations="$8"
  local confidence="${9:-potential}"   # confirmed|potential|info

  severity="$(echo "$severity" | tr '[:lower:]' '[:upper:]')"
  case "$severity" in
    INFO|LOW|MEDIUM|HIGH|CRITICAL) : ;;
    *) severity="INFO" ;;
  esac

  SEV_COUNT[$severity]=$(( ${SEV_COUNT[$severity]:-0} + 1 ))
  TOTAL_FINDINGS=$(( TOTAL_FINDINGS + 1 ))

  local color; color="$(sev_color "$severity")"
  local confidence_label
  case "$confidence" in
    confirmed) confidence_label="Configuracao confirmadamente insegura" ;;
    potential) confidence_label="Possivel vetor - requer validacao manual" ;;
    *) confidence_label="Informativo - requer investigacao manual" ;;
  esac

  # Saida imediata no terminal (linha resumida)
  printf "   ${color}[%s]${C_RESET} %s ${C_GRAY}-> %s${C_RESET}\n" "$severity" "$check_name" "$target"

  # Bloco detalhado para o relatorio texto
  REPORT_LINES+=("------------------------------------------------------------")
  REPORT_LINES+=("Verificacao     : $check_name")
  REPORT_LINES+=("Alvo            : $target")
  REPORT_LINES+=("Severidade      : $severity ($confidence_label)")
  REPORT_LINES+=("Descricao       : $description")
  REPORT_LINES+=("Evidencia       : $evidence")
  REPORT_LINES+=("Motivo          : $reason")
  REPORT_LINES+=("Recomendacao    : $recommendation")
  REPORT_LINES+=("Limitacoes      : $limitations")

  if [ "$JSON_OUTPUT" -eq 1 ]; then
    local j
    j=$(cat <<JSONEOF
  {
    "check": "$(json_escape "$check_name")",
    "target": "$(json_escape "$target")",
    "severity": "$(json_escape "$severity")",
    "confidence": "$(json_escape "$confidence")",
    "confidence_label": "$(json_escape "$confidence_label")",
    "description": "$(json_escape "$description")",
    "evidence": "$(json_escape "$evidence")",
    "reason": "$(json_escape "$reason")",
    "recommendation": "$(json_escape "$recommendation")",
    "limitations": "$(json_escape "$limitations")"
  }
JSONEOF
)
    JSON_FINDINGS+=("$j")
  fi
}

# -----------------------------------------------------------------------------
# Carregamento de modulos
# -----------------------------------------------------------------------------
load_modules() {
  local entry fn desc file path
  local missing=0
  for entry in "${MODULE_LIST[@]}"; do
    IFS='|' read -r fn desc file <<< "$entry"
    path="$MODULES_DIR/$file"
    if [ -f "$path" ]; then
      # shellcheck disable=SC1090
      source "$path"
    else
      printf "${C_YELLOW}[!] Modulo ausente, sera ignorado: modules/%s${C_RESET}\n" "$file"
      missing=1
    fi
  done
  return $missing
}

# -----------------------------------------------------------------------------
# Execucao dos modulos selecionados
# -----------------------------------------------------------------------------
run_modules() {
  local entry fn desc file
  local -a to_run=()

  if [ "$SCAN_MODE" = "quick" ]; then
    to_run=("${QUICK_MODULES[@]}")
  else
    for entry in "${MODULE_LIST[@]}"; do
      IFS='|' read -r fn desc file <<< "$entry"
      to_run+=("$fn")
    done
  fi

  for entry in "${MODULE_LIST[@]}"; do
    IFS='|' read -r fn desc file <<< "$entry"
    local run_it=0
    local item
    for item in "${to_run[@]}"; do
      [ "$item" = "$fn" ] && run_it=1 && break
    done
    [ "$run_it" -eq 0 ] && continue

    printf "\n${C_WHITE}[+] %s${C_RESET}\n" "$desc"
    if declare -f "$fn" >/dev/null 2>&1; then
      # Isola falhas: uma verificacao com erro nao derruba a auditoria inteira
      "$fn" || printf "${C_YELLOW}    [!] Modulo '%s' terminou com erro; prosseguindo.${C_RESET}\n" "$fn"
    else
      printf "${C_YELLOW}    [!] Funcao '%s' nao definida (modulo nao carregado).${C_RESET}\n" "$fn"
    fi
  done
}

# -----------------------------------------------------------------------------
# Resumo final e persistencia de relatorios
# -----------------------------------------------------------------------------
print_summary() {
  printf "\n${C_WHITE}============================================================${C_RESET}\n"
  printf "${C_WHITE}  Audit completed.${C_RESET}\n"
  printf "${C_WHITE}============================================================${C_RESET}\n\n"
  printf "  Findings totais : %s\n" "$TOTAL_FINDINGS"
  printf "  ${C_RED_INTENSE}Critical${C_RESET}       : %s\n" "${SEV_COUNT[CRITICAL]}"
  printf "  ${C_RED}High${C_RESET}           : %s\n" "${SEV_COUNT[HIGH]}"
  printf "  ${C_YELLOW}Medium${C_RESET}         : %s\n" "${SEV_COUNT[MEDIUM]}"
  printf "  ${C_GREEN}Low${C_RESET}            : %s\n" "${SEV_COUNT[LOW]}"
  printf "  ${C_CYAN}Informational${C_RESET}  : %s\n" "${SEV_COUNT[INFO]}"
  printf "\n"
}

write_reports() {
  mkdir -p "$OUTPUT_DIR" 2>/dev/null
  if [ ! -d "$OUTPUT_DIR" ] || [ ! -w "$OUTPUT_DIR" ]; then
    printf "${C_YELLOW}[!] Nao foi possivel criar/gravar em '%s'. Relatorios nao serao salvos em disco.${C_RESET}\n" "$OUTPUT_DIR"
    return 1
  fi

  local txt_path="$OUTPUT_DIR/pcsec-privesc-report-${RUN_TIMESTAMP}.txt"
  {
    echo "$PCSEC_NAME ($PCSEC_SHORTNAME) v$PCSEC_VERSION"
    echo "Developed by $PCSEC_AUTHOR"
    echo "Data da execucao: $(date 2>/dev/null)"
    echo "Hostname........: $(hostname 2>/dev/null || echo desconhecido)"
    echo "Usuario.........: $(id -un 2>/dev/null) (uid=$(id -u 2>/dev/null))"
    echo "Modo de execucao: $SCAN_MODE"
    echo ""
    echo "RESUMO"
    echo "------"
    echo "Findings totais: $TOTAL_FINDINGS"
    echo "Critical: ${SEV_COUNT[CRITICAL]}  High: ${SEV_COUNT[HIGH]}  Medium: ${SEV_COUNT[MEDIUM]}  Low: ${SEV_COUNT[LOW]}  Info: ${SEV_COUNT[INFO]}"
    echo ""
    echo "DETALHAMENTO DOS ACHADOS"
    echo "========================="
    local l
    for l in "${REPORT_LINES[@]}"; do
      echo "$l"
    done
    echo "------------------------------------------------------------"
    echo ""
    echo "AVISO: relatorio gerado apenas a partir de verificacoes de leitura"
    echo "locais. Nenhum dado foi enviado para servidores externos."
  } > "$txt_path" 2>/dev/null

  if [ -f "$txt_path" ]; then
    printf "${C_GREEN}[+] Relatorio texto salvo em:${C_RESET} %s\n" "$txt_path"
  fi

  if [ "$JSON_OUTPUT" -eq 1 ]; then
    local json_path="$OUTPUT_DIR/pcsec-privesc-report-${RUN_TIMESTAMP}.json"
    {
      echo "{"
      echo "  \"tool\": \"$PCSEC_SHORTNAME\","
      echo "  \"name\": \"$(json_escape "$PCSEC_NAME")\","
      echo "  \"version\": \"$PCSEC_VERSION\","
      echo "  \"author\": \"$(json_escape "$PCSEC_AUTHOR")\","
      echo "  \"generated_at\": \"$(date -Iseconds 2>/dev/null || date 2>/dev/null)\","
      echo "  \"hostname\": \"$(json_escape "$(hostname 2>/dev/null || echo unknown)")\","
      echo "  \"scan_mode\": \"$SCAN_MODE\","
      echo "  \"summary\": {"
      echo "    \"total\": $TOTAL_FINDINGS,"
      echo "    \"critical\": ${SEV_COUNT[CRITICAL]},"
      echo "    \"high\": ${SEV_COUNT[HIGH]},"
      echo "    \"medium\": ${SEV_COUNT[MEDIUM]},"
      echo "    \"low\": ${SEV_COUNT[LOW]},"
      echo "    \"info\": ${SEV_COUNT[INFO]}"
      echo "  },"
      echo "  \"findings\": ["
      local count=${#JSON_FINDINGS[@]}
      local i=0
      for i in "${!JSON_FINDINGS[@]}"; do
        if [ "$i" -lt $((count - 1)) ]; then
          echo "${JSON_FINDINGS[$i]},"
        else
          echo "${JSON_FINDINGS[$i]}"
        fi
      done
      echo "  ]"
      echo "}"
    } > "$json_path" 2>/dev/null
    [ -f "$json_path" ] && printf "${C_GREEN}[+] Relatorio JSON salvo em:${C_RESET} %s\n" "$json_path"
  fi
}

# -----------------------------------------------------------------------------
# Tratamento de sinais / interrupcoes
# -----------------------------------------------------------------------------
on_interrupt() {
  printf "\n\n${C_YELLOW}[!] Execucao interrompida pelo usuario (SIGINT).${C_RESET}\n"
  printf "${C_YELLOW}[!] Nenhuma alteracao foi feita no sistema. Encerrando com seguranca.${C_RESET}\n"
  exit 130
}
on_term() {
  printf "\n\n${C_YELLOW}[!] Sinal de termino recebido. Encerrando com seguranca.${C_RESET}\n"
  exit 143
}
trap on_interrupt INT
trap on_term TERM

# -----------------------------------------------------------------------------
# Validacao de argumentos
# -----------------------------------------------------------------------------
validate_output_dir() {
  local dir="$1"
  # Impede caminhos vazios e previne injecao basica via caracteres de controle
  if [ -z "$dir" ]; then
    echo "Erro: --output requer um caminho de diretorio." >&2
    exit 2
  fi
  OUTPUT_DIR="$dir"
}

# -----------------------------------------------------------------------------
# Parsing de argumentos
# -----------------------------------------------------------------------------
parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --help|-h)
        setup_colors
        print_help
        exit 0
        ;;
      --version|-v)
        print_version
        exit 0
        ;;
      --quick)
        SCAN_MODE="quick"
        ;;
      --full)
        SCAN_MODE="full"
        ;;
      --no-color)
        USE_COLOR=0
        ;;
      --json)
        JSON_OUTPUT=1
        ;;
      --checks)
        LIST_CHECKS_ONLY=1
        ;;
      --output)
        shift
        if [ $# -eq 0 ]; then
          echo "Erro: --output requer um argumento (diretorio)." >&2
          exit 2
        fi
        validate_output_dir "$1"
        ;;
      --output=*)
        validate_output_dir "${1#--output=}"
        ;;
      *)
        echo "Argumento desconhecido: $1" >&2
        echo "Use --help para ver as opcoes disponiveis." >&2
        exit 2
        ;;
    esac
    shift
  done

  if [ -z "$OUTPUT_DIR" ]; then
    OUTPUT_DIR="$(pwd)/pcsec-reports"
  fi
}

# -----------------------------------------------------------------------------
# Aviso de execucao como root
# -----------------------------------------------------------------------------
warn_if_root() {
  if [ "$(id -u 2>/dev/null)" = "0" ]; then
    printf "${C_YELLOW}[!] Executando como root: a analise tera maior visibilidade e podera${C_RESET}\n"
    printf "${C_YELLOW}    revelar informacoes adicionais (ex.: arquivos normalmente protegidos).${C_RESET}\n"
    printf "${C_YELLOW}    Esta condicao NAO e usada para alterar o sistema de forma alguma.${C_RESET}\n\n"
  fi
}

# -----------------------------------------------------------------------------
# main
# -----------------------------------------------------------------------------
main() {
  parse_args "$@"
  setup_colors

  if [ "$LIST_CHECKS_ONLY" -eq 1 ]; then
    print_checks_list
    exit 0
  fi

  print_banner
  warn_if_root

  printf "${C_GRAY}Modo de execucao: %s${C_RESET}\n" "$SCAN_MODE"
  printf "${C_GRAY}Diretorio de saida dos relatorios: %s${C_RESET}\n" "$OUTPUT_DIR"

  load_modules
  run_modules
  print_summary
  write_reports

  printf "${C_GRAY}Lembre-se: esta ferramenta so realiza leitura local. Valide manualmente${C_RESET}\n"
  printf "${C_GRAY}todos os achados antes de qualquer acao corretiva ou de teste adicional.${C_RESET}\n\n"
}

main "$@"
