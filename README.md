# PabloCyberSec Linux Privilege Escalation (PCSEC-PRIVESC)

```
  ____   ____ ____  _____ ____
 |  _ \ / ___/ ___|| ____/ ___|
 | |_) | |   \___ \|  _|| |
 |  __/| |___ ___) | |__| |___
 |_|    \____|____/|_____\____|

  PABLOCYBERSEC
  LINUX PRIVILEGE ESCALATION
  Security Auditing & Misconfiguration Analysis
  Developed by PabloCyberSec
  Version 1.0.0
```

> Auditoria local de seguranca em sistemas Linux, com foco em identificar
> configuracoes inseguras e possiveis vetores de escalacao de privilegios —
> **sem executar exploits, sem alterar o sistema e sem enviar dados para
> servidores externos.**

---

## Sumario

- [Sobre o projeto](#sobre-o-projeto)
- [Objetivos](#objetivos)
- [Funcionalidades](#funcionalidades)
- [Requisitos](#requisitos)
- [Instalacao](#instalacao)
- [Uso](#uso)
- [Argumentos disponiveis](#argumentos-disponiveis)
- [Niveis de severidade](#niveis-de-severidade)
- [Exemplo de relatorio](#exemplo-de-relatorio)
- [Estrutura do repositorio](#estrutura-do-repositorio)
- [Limitacoes conhecidas](#limitacoes-conhecidas)
- [Avisos de seguranca e uso responsavel](#avisos-de-seguranca-e-uso-responsavel)
- [Licenca](#licenca)
- [Creditos](#creditos)

---

## Sobre o projeto

**PabloCyberSec Linux Privilege Escalation** (nome curto: **PCSEC-PRIVESC**) e
uma ferramenta de linha de comando, escrita em Bash, que realiza verificacoes
locais de seguranca em sistemas Linux e aponta configuracoes que podem
representar vetores de escalacao de privilegios — como regras `sudo`
excessivas, binarios com `SUID`/`SGID` ou *capabilities* perigosas,
permissoes incorretas em arquivos criticos, tarefas `cron` inseguras, entre
outros.

O projeto foi desenhado para profissionais de seguranca ofensiva e defensiva,
equipes de *red team*/*blue team*, administradores de sistemas e estudantes
que precisam avaliar, de forma rapida e organizada, a postura de seguranca de
um host Linux **em ambientes autorizados**.

## Objetivos

- Identificar **configuracoes inseguras** e **permissoes excessivas**.
- Apontar **possiveis vetores** de escalacao de privilegios que exigem
  validacao manual.
- Gerar **relatorios claros**, classificados por severidade, com recomendacao
  de correcao para cada achado.
- Funcionar de forma **segura por padrao**: somente leitura, sem exploits, sem
  modificar o sistema e sem exfiltrar dados.

## Funcionalidades

A ferramenta executa os seguintes modulos de auditoria:

| Modulo | O que verifica |
|---|---|
| **System Enumeration** | Distro, kernel, arquitetura, usuario/UID, grupos, uptime, hostname, indicios de container, variaveis de ambiente sensiveis (sem expor valores) e ferramentas administrativas disponiveis. |
| **Sudo Configuration Audit** | Regras `sudo` acessiveis ao usuario atual (via `sudo -n -l`, nunca solicita senha), identificando binarios classicamente associados a escalacao via `sudo`. |
| **SUID / SGID Audit** | Arquivos com bit `SUID`/`SGID` em diretorios padrao de binarios, com destaque para programas frequentemente citados em tecnicas publicas de escalacao. |
| **Linux Capabilities** | *Capabilities* configuradas em arquivos (via `getcap`), destacando as de maior impacto (ex. `cap_setuid`, `cap_sys_admin`). |
| **Process & Service Audit** | Processos rodando como root visiveis ao usuario, binarios de processos graviaveis pelo usuario atual, e permissao de escrita em diretorios de unidades `systemd`. |
| **Scheduled Tasks (Cron) Audit** | Crontab do usuario, permissao de escrita em `/etc/crontab` e em `/etc/cron.*`, e scripts cron graviaveis por terceiros. |
| **File Permission Analysis** | Variavel `PATH` (incluindo `.` ou diretorios graviaveis por terceiros), permissao de arquivos sensiveis (`/etc/passwd`, `/etc/shadow`, etc. — **sem ler o conteudo**), diretorios home e arquivos de inicializacao de shell graviaveis por outros. |
| **Kernel & Update Audit** | Versao do kernel e do SO para correlacao manual com bases de CVE, indicios de reboot pendente e gerenciador de pacotes disponivel. |

> A ferramenta **nunca** executa exploits, **nunca** tenta obter root
> automaticamente e **nunca** imprime conteudo de arquivos sensiveis, tokens,
> senhas ou chaves privadas — valores desse tipo sao sempre redigidos
> (`[REDACTED]`) quando sua simples existencia precisa ser reportada.

## Requisitos

- Bash 4.x ou superior (presente por padrao na maioria das distribuicoes Linux
  modernas).
- Utilitarios padrao do sistema: `find`, `stat`, `ps`, `uname`, `id`, `grep`,
  `awk`.
- Opcionais (a ferramenta detecta e avisa quando ausentes, sem travar a
  execucao):
  - `getcap` (pacote `libcap2-bin` no Debian/Ubuntu) — para o modulo de
    *capabilities*.
  - `systemctl` — para a analise de servicos `systemd`.
  - `sudo` — para a auditoria de regras sudo.
- **Nao requer privilegios root** para as verificacoes basicas. Quando
  executada como root, a ferramenta exibe um aviso informando que a analise
  tera maior visibilidade — essa condicao nunca e usada para alterar o
  sistema.

## Instalacao

### Opcao 1 — Download do script (recomendado)

```bash
curl -fsSL "https://raw.githubusercontent.com/<SEU_USUARIO>/pablocybersec-linux-privesc/main/pcsec-privesc.sh" -o pcsec-privesc.sh
chmod +x pcsec-privesc.sh
./pcsec-privesc.sh --help
```

> Substitua `<SEU_USUARIO>` pelo usuario/organizacao real do repositorio
> publicado no GitHub. Este README nao assume uma URL de publicacao
> definitiva — ajuste para o endereco real do seu fork/repositorio antes de
> divulgar instrucoes de instalacao.

Para obter o projeto completo (com todos os modulos em `modules/`), clone o
repositorio:

```bash
git clone https://github.com/<SEU_USUARIO>/pablocybersec-linux-privesc.git
cd pablocybersec-linux-privesc
chmod +x pcsec-privesc.sh
./pcsec-privesc.sh --full
```

### Verificando o conteudo antes de executar

Antes de rodar qualquer script baixado da internet — inclusive este — é uma
boa pratica de seguranca **inspecionar o conteudo**:

```bash
less pcsec-privesc.sh          # leia o script antes de executar
sha256sum pcsec-privesc.sh     # compare com um hash publicado, se disponivel
```

### Opcao 2 — Execucao via pipe para o Bash (nao recomendada sem inspecao previa)

```bash
curl -fsSL "https://raw.githubusercontent.com/<SEU_USUARIO>/pablocybersec-linux-privesc/main/pcsec-privesc.sh" | bash
```

⚠️ **Executar codigo baixado diretamente via pipe para o Bash, sem inspecionar
o conteudo antes, nao e a opcao mais segura** — você perde a chance de revisar
o que sera executado na sua maquina. Prefira sempre baixar o arquivo, lê-lo
(ou ao menos conferir seu hash) e só então executá-lo.

Veja mais detalhes em [`docs/INSTALL.md`](docs/INSTALL.md).

## Uso

```bash
./pcsec-privesc.sh --full
./pcsec-privesc.sh --quick --no-color
./pcsec-privesc.sh --full --json --output /tmp/auditoria-$(hostname)
./pcsec-privesc.sh --checks
```

Mais exemplos em [`docs/USAGE.md`](docs/USAGE.md).

### Saida de exemplo (ilustrativa)

```
PABLOCYBERSEC LINUX PRIVILEGE ESCALATION

[+] System Enumeration
[+] Sudo Configuration Audit
[+] SUID / SGID Audit
[+] Linux Capabilities
[+] Scheduled Tasks (Cron) Audit
[+] File Permission Analysis
[+] Service Configuration Audit

Audit completed.

Findings: 12
High Risk: 2
Medium Risk: 5
Informational: 5
```

> Os numeros acima sao apenas ilustrativos. Os resultados reais dependem
> inteiramente do sistema auditado e das verificacoes executadas naquela
> sessao.

## Argumentos disponiveis

| Argumento | Descricao |
|---|---|
| `--help` | Mostra a ajuda e encerra. |
| `--version` | Mostra a versao da ferramenta e encerra. |
| `--quick` | Executa apenas as verificacoes basicas (System Enumeration, Sudo, SUID/SGID e Kernel — subconjunto mais rapido). |
| `--full` | Executa **todas** as verificacoes implementadas (padrao quando nenhum modo e informado). |
| `--no-color` | Desativa cores ANSI na saida do terminal. |
| `--output DIR` | Define o diretorio onde os relatorios serao salvos (padrao: `./pcsec-reports`). |
| `--json` | Alem do relatorio em texto, gera um relatorio estruturado em JSON. |
| `--checks` | Lista todos os modulos/verificacoes disponiveis e encerra. |

## Niveis de severidade

Cada achado recebe uma classificacao de severidade e um nivel de confianca:

| Severidade | Significado |
|---|---|
| **Informativo** | Dado de contexto; nao representa, por si so, um risco de seguranca. |
| **Baixo** | Configuracao que merece atencao, mas com baixa probabilidade/impacto de exploracao. |
| **Medio** | Configuracao que pode facilitar um ataque, mas normalmente exige condicoes adicionais. |
| **Alto** | Configuracao fortemente associada a tecnicas conhecidas de escalacao de privilegios. |
| **Critico** | Configuracao que, isoladamente, ja representa um caminho direto e de alta confianca para comprometimento do sistema (ex.: `/etc/shadow` gravavel). |

Alem da severidade, cada achado traz um **nivel de confianca**:

- **Configuracao confirmadamente insegura** — a condicao foi verificada
  diretamente (ex.: teste de permissao de escrita bem-sucedido).
- **Possivel vetor — requer validacao manual** — o indicio foi encontrado,
  mas a exploracao real depende de fatores que a ferramenta nao confirma
  automaticamente.
- **Informativo — requer investigacao manual** — dado de contexto que o
  profissional deve analisar por conta propria.

A ferramenta **nunca afirma que e possivel obter root** apenas com base em um
unico achado isolado, sem evidencia suficiente.

## Exemplo de relatorio

Cada achado no relatorio (texto ou JSON) segue esta estrutura:

```
------------------------------------------------------------
Verificacao     : Scheduled Tasks (Cron) Audit
Alvo            : /etc/cron.d
Severidade      : CRITICAL (Configuracao confirmadamente insegura)
Descricao       : Diretorio de tarefas agendadas do sistema e gravavel
                  pelo usuario atual.
Evidencia       : Teste de permissao: diretorio gravavel = sim
Motivo          : Scripts colocados neste diretorio sao tipicamente
                  executados pelo cron do sistema com privilegios de root.
Recomendacao    : Corrija a permissao do diretorio imediatamente para
                  restringir escrita apenas a root.
Limitacoes      : Nenhum arquivo foi criado neste diretorio por esta
                  ferramenta.
```

No modo `--json`, o mesmo achado e emitido como um objeto estruturado dentro
de um array `findings`, pronto para integracao com outras ferramentas (SIEM,
dashboards, pipelines de CI/CD de hardening, etc.).

## Estrutura do repositorio

```
pablocybersec-linux-privesc/
├── pcsec-privesc.sh        # script principal (motor, banner, CLI, relatorios)
├── README.md
├── LICENSE
├── .gitignore
├── docs/
│   ├── INSTALL.md
│   ├── USAGE.md
│   ├── FINDINGS.md
│   └── SECURITY.md
├── modules/
│   ├── system_info.sh
│   ├── sudo_audit.sh
│   ├── suid_sgid.sh
│   ├── capabilities.sh
│   ├── process_audit.sh
│   ├── cron_audit.sh
│   ├── permission_audit.sh
│   └── kernel_audit.sh
└── tests/
    └── test_basic.sh
```

O script principal verifica a existencia de cada modulo antes de carrega-lo;
se um modulo estiver ausente, a auditoria continua com um aviso, sem
interromper os demais.

## Limitacoes conhecidas

- As listas de binarios/*capabilities* de referencia usadas para priorizar
  achados **nao sao exaustivas** e podem gerar falsos positivos ou negativos.
- A ferramenta **nao consulta bases de CVE automaticamente**; a correlacao
  entre versao de kernel/SO e vulnerabilidades conhecidas e sempre manual.
- Verificacoes que dependem de ferramentas opcionais (`getcap`, `systemctl`,
  `sudo`) sao puladas de forma segura quando essas ferramentas nao estao
  disponiveis.
- A visibilidade de processos, regras `sudo` e arquivos depende diretamente
  do usuario com o qual a ferramenta e executada; rodar como usuario comum
  trara uma visao mais limitada do que rodar como root.
- Esta ferramenta **nao substitui** uma avaliacao manual aprofundada feita por
  um profissional de seguranca qualificado.

## Avisos de seguranca e uso responsavel

- Use esta ferramenta **apenas em sistemas para os quais voce possui
  autorizacao explicita** (ambiente proprio, laboratorio, ou contrato formal
  de pentest/auditoria).
- A ferramenta **nao executa exploits**, **nao escala privilegios
  automaticamente**, **nao modifica arquivos do sistema** e **nao desativa
  mecanismos de seguranca**.
- A ferramenta **nao transmite nenhum dado para servidores externos** — toda
  a analise e local, e os relatorios gerados ficam apenas no diretorio de
  saida escolhido por voce.
- Segredos, tokens, senhas e chaves privadas eventualmente encontrados **nunca
  sao impressos integralmente**; apenas sua presenca e sinalizada, com o valor
  redigido.
- Consulte [`docs/SECURITY.md`](docs/SECURITY.md) para a politica completa de
  divulgacao de problemas de seguranca no proprio projeto.

## Licenca

Este projeto esta licenciado sob a [Licenca MIT](LICENSE), que inclui um aviso
adicional de uso responsavel.

## Creditos

**Developed by PabloCyberSec.**
