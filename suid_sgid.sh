#!/usr/bin/env bash
#
# modules/suid_sgid.sh
# Modulo: Identificacao de arquivos com bits SUID/SGID.
# Apenas leitura e listagem. Nenhum arquivo encontrado e executado.

# Binarios comumente citados em guias publicos de escalacao quando possuem
# SUID setado de forma incomum (fora do pacote padrao da distro).
_PCSEC_SUID_WATCHLIST=(
  "nmap" "vim" "find" "bash" "sh" "python" "python3" "perl" "awk" "env"
  "less" "more" "cp" "mv" "tar" "nc" "ncat" "socat" "php" "ruby" "lua"
  "docker" "gdb" "node"
)

_pcsec_suid_search_dirs() {
  # Diretorios tipicos onde SUID/SGID relevantes costumam residir.
  # Evita montagens virtuais (/proc, /sys) e pontos de montagem de rede.
  echo "/usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /bin /sbin /opt"
}

module_suid_sgid() {
  if ! has_cmd find; then
    report_finding \
      "SUID / SGID Audit" \
      "find (binario)" \
      "O comando 'find' nao esta disponivel; a varredura de SUID/SGID foi pulada." \
      "command -v find -> nao encontrado" \
      "INFO" \
      "Sem 'find', esta verificacao nao pode ser executada neste ambiente." \
      "Instale coreutils/findutils para permitir esta verificacao em execucoes futuras." \
      "Nenhum dado coletado nesta execucao." \
      "info"
    return 0
  fi

  local dirs
  dirs="$(_pcsec_suid_search_dirs)"

  local suid_count=0
  local sgid_count=0
  local listing
  # -xdev evita cruzar para sistemas de arquivos montados (ex.: /proc via bind),
  # reduzindo ruido de pseudo-filesystems e montagens de rede.
  listing="$(find $dirs -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null)"

  if [ -z "$listing" ]; then
    report_finding \
      "SUID / SGID Audit" \
      "Diretorios padrao de binarios" \
      "Nenhum arquivo com bit SUID ou SGID foi encontrado nos diretorios verificados." \
      "Diretorios pesquisados: $dirs" \
      "INFO" \
      "Ausencia de resultados pode indicar ambiente restrito ou permissao insuficiente para listar alguns caminhos." \
      "Nenhuma acao imediata. Considere repetir a verificacao com privilegios elevados se autorizado." \
      "A busca foi limitada a diretorios comuns; caminhos nao padrao nao foram verificados." \
      "info"
    return 0
  fi

  while IFS= read -r filepath; do
    [ -z "$filepath" ] && continue
    [ ! -e "$filepath" ] && continue

    local perms owner group ftype base is_watch=0
    perms="$(stat -c '%A' "$filepath" 2>/dev/null || echo "desconhecido")"
    owner="$(stat -c '%U' "$filepath" 2>/dev/null || echo "desconhecido")"
    group="$(stat -c '%G' "$filepath" 2>/dev/null || echo "desconhecido")"
    ftype="arquivo regular"
    [ -L "$filepath" ] && ftype="link simbolico"

    base="$(basename "$filepath")"
    local watch
    for watch in "${_PCSEC_SUID_WATCHLIST[@]}"; do
      if [ "$base" = "$watch" ]; then
        is_watch=1
        break
      fi
    done

    local has_suid=0 has_sgid=0
    case "$perms" in
      *s??------) : ;;
    esac
    [ -u "$filepath" ] && has_suid=1
    [ -g "$filepath" ] && has_sgid=1

    [ "$has_suid" -eq 1 ] && suid_count=$((suid_count + 1))
    [ "$has_sgid" -eq 1 ] && sgid_count=$((sgid_count + 1))

    local bit_desc=""
    [ "$has_suid" -eq 1 ] && bit_desc="SUID"
    if [ "$has_sgid" -eq 1 ]; then
      [ -n "$bit_desc" ] && bit_desc="$bit_desc + SGID" || bit_desc="SGID"
    fi

    if [ "$is_watch" -eq 1 ]; then
      report_finding \
        "SUID / SGID Audit" \
        "$filepath" \
        "Binario presente em lista de referencia de programas frequentemente citados em tecnicas de escalacao quando possuem bit $bit_desc." \
        "Permissoes: $perms | Dono: $owner | Grupo: $group | Tipo: $ftype" \
        "HIGH" \
        "Binarios desta natureza, quando com $bit_desc, sao documentados publicamente (ex. GTFOBins) como potenciais vetores para obtencao de shell privilegiado." \
        "Avalie se o bit $bit_desc e realmente necessario para este binario; remova com 'chmod' se nao for, apos validacao." \
        "Presenca na lista de referencia nao confirma exploracao; o pacote padrao da distribuicao pode legitimamente definir este bit. Validacao manual e necessaria." \
        "potential"
    else
      report_finding \
        "SUID / SGID Audit" \
        "$filepath" \
        "Arquivo com bit $bit_desc identificado durante a varredura padrao." \
        "Permissoes: $perms | Dono: $owner | Grupo: $group | Tipo: $ftype" \
        "LOW" \
        "Muitos binarios do sistema operacional exigem SUID/SGID para funcionar corretamente (ex. passwd, mount)." \
        "Revise se o binario e esperado nesta versao da distribuicao; compare com uma instalacao limpa se houver duvida." \
        "Classificacao conservadora: a ferramenta nao possui uma lista completa de binarios legitimos de cada distribuicao." \
        "info"
    fi
  done <<< "$listing"

  report_finding \
    "SUID / SGID Audit" \
    "Resumo da varredura" \
    "Totais consolidados de arquivos com bits especiais encontrados." \
    "SUID: $suid_count | SGID: $sgid_count" \
    "INFO" \
    "Resumo quantitativo para referencia rapida." \
    "Revise individualmente os achados classificados como MEDIUM/HIGH acima." \
    "Numeros refletem apenas os diretorios pesquisados nesta execucao." \
    "info"
}
