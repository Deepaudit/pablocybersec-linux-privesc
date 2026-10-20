#!/usr/bin/env bash
#
# modules/kernel_audit.sh
# Modulo: Informacoes de kernel e sistema operacional para correlacao manual
# com bases de vulnerabilidades conhecidas (CVE). Esta ferramenta NAO afirma
# que uma vulnerabilidade e explorável apenas com base na versao encontrada,
# e NAO executa exploits de kernel sob nenhuma circunstancia.

module_kernel_audit() {
  local kernel_version os_pretty

  kernel_version="$(uname -r 2>/dev/null || echo desconhecida)"

  os_pretty="desconhecida"
  if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    os_pretty="$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-desconhecida}")"
  fi

  report_finding \
    "Kernel & Update Audit" \
    "uname -r" \
    "Versao do kernel em execucao, util para correlacao manual com bases publicas de CVE." \
    "Kernel: $kernel_version | SO: $os_pretty" \
    "INFO" \
    "A versao do kernel, isoladamente, nao comprova a presenca de uma vulnerabilidade explorável." \
    "Compare manualmente esta versao com os boletins de seguranca da distribuicao e com bases como NVD/CVE antes de qualquer conclusao." \
    "Esta ferramenta nao consulta bases de CVE automaticamente e nao tenta confirmar exploracao." \
    "info"

  # Verifica se ha indicacao de reboot pendente (comum apos atualizacoes de kernel)
  if [ -f /var/run/reboot-required ]; then
    report_finding \
      "Kernel & Update Audit" \
      "/var/run/reboot-required" \
      "O sistema sinaliza que ha atualizacoes aplicadas que exigem reinicializacao." \
      "Arquivo /var/run/reboot-required presente" \
      "MEDIUM" \
      "Ate a reinicializacao, o kernel em execucao pode nao conter correcoes de seguranca ja instaladas em disco." \
      "Agende uma janela de manutencao para reiniciar o sistema e aplicar o kernel atualizado." \
      "A presenca deste arquivo e especifica de distribuicoes baseadas em Debian/Ubuntu." \
      "confirmed"
  fi

  # Verifica gerenciador de pacotes disponivel, apenas para indicar se e possivel checar updates manualmente
  local pkg_mgr=""
  if has_cmd apt; then pkg_mgr="apt"; fi
  if has_cmd dnf; then pkg_mgr="dnf"; fi
  if has_cmd yum; then pkg_mgr="yum"; fi
  if has_cmd pacman; then pkg_mgr="pacman"; fi
  if has_cmd zypper; then pkg_mgr="zypper"; fi

  if [ -n "$pkg_mgr" ]; then
    report_finding \
      "Kernel & Update Audit" \
      "Gerenciador de pacotes: $pkg_mgr" \
      "Gerenciador de pacotes identificado, util para o profissional checar manualmente atualizacoes de seguranca disponiveis." \
      "Comando detectado no PATH: $pkg_mgr" \
      "INFO" \
      "Informacao de apoio; esta ferramenta nao executa atualizacoes nem instala pacotes." \
      "Execute a checagem de atualizacoes do seu gerenciador de pacotes de forma manual e autorizada (ex. 'apt list --upgradable')." \
      "Nenhum comando de atualizacao foi executado por esta ferramenta." \
      "info"
  fi
}
