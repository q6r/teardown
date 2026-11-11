<p align="center">
  <img src="assets/banner.svg" alt="teardown: triagem estática de binários e apps. Cada achado traz sua evidência e seus limites." width="100%">
</p>

**Aponte para um arquivo e descubra o que ele é e o que merece uma segunda olhada. Cada conclusão vem com a evidência e com os motivos pelos quais pode estar errada, e o arquivo nunca é executado.** Um único binário em Go, só com a biblioteca padrão: uma CLI, uma API HTTP com painel ao vivo e um servidor MCP para agentes de IA.

[![Go 1.24+](https://img.shields.io/badge/go-1.24%2B-00ADD8)](go.mod)
[![Licença: MIT](https://img.shields.io/badge/licen%C3%A7a-MIT-green)](LICENSE)
[![Dependências: nenhuma](https://img.shields.io/badge/depend%C3%AAncias-nenhuma-brightgreen)](go.mod)
[![CI](https://github.com/q6r/teardown/actions/workflows/ci.yml/badge.svg)](https://github.com/q6r/teardown/actions/workflows/ci.yml)

[English](README.md) · Português

<p align="center">
  <img src="docs/screenshots/hero.png" alt="O painel do teardown mostrando o relatório de dropper.bin: a barra de navegação, o caminho de navegação e as abas das seções, pontuação de risco crítica 100, hashes com botões de copiar e o primeiro dos 19 achados com evidências e limitações" width="100%">
</p>
<p align="center"><sub>O relatório do painel para <code>dropper.bin</code>, um arquivo sintético inofensivo que só parece um dropper para um scanner estático (<code>go run ./examples/gensamples -dropper</code>).</sub></p>

## Por quê

- **Evidência, não veredito.** Um achado é `{id, title, severity, evidence[], limitations[]}`, e um teste falha se algum não tiver evidência ou limitações. A pontuação de risco de 0 a 100 mostra a própria conta. Ela ordena uma fila de revisão; não diz que algo é malware.
- **Seguro para apontar contra arquivos hostis.** Nada é carregado, executado, avaliado ou descompactado além de pequenos metadados limitados. Os parsers têm limites, são canceláveis, resistem a pânico e passam por fuzzing. Os envios ficam em um diretório privado e são apagados assim que a análise termina.
- **Um binário, quatro portas de entrada.** Relatório no terminal, JSON para CI, um painel e um relatório HTML autocontido para pessoas, ferramentas MCP para agentes. Todos chamam o mesmo motor, então não têm como discordar entre si.

## Recursos

- **Formatos.** PE (EXE, DLL, drivers, .NET, hash de importação), ELF com verificação de endurecimento no estilo checksec, Mach-O incluindo binários fat, informações de build do Go, a família ZIP detectada pelo conteúdo (JAR, APK, AAB, Office, ODF, EPUB, NuGet, wheel, VSIX) com heurísticas de zip-slip e zip-bomb, ASAR do Electron com indícios de configurações arriscadas, WebAssembly e modelos GGUF. Os outros tipos (PDF, SQLite, safetensors, imagens, formatos de compressão, scripts) são reconhecidos e recebem a análise genérica; o relatório avisa que não existe parser específico para o formato.
- **Uma única passada em streaming** para MD5, SHA-1, SHA-256, entropia de Shannon (total e em até 512 janelas) e extração de strings (ASCII e UTF-16LE).
- **Strings que dizem alguma coisa.** Classificadas em URLs, domínios, IPs, e-mails, caminhos, chaves de registro, comandos, user agents, nomes de API, base64 e hex. Segredos (chaves AWS, tokens do GitHub e do Slack, chaves PEM, JWTs) são ocultados em toda saída: quatro caracteres e o tamanho, nunca o valor.
- **Achados com pontuação documentada.** Empacotamento, seções RWX, endurecimento ausente, grupos suspeitos de importações, indicadores embutidos, zip-slip, configurações arriscadas de Electron e Android, vazamentos de privacidade como caminhos de PDB. [Catálogo e pontuação](docs/rules.md).
- **CLI** com `analyze`, `strings`, `hash`, `diff`, `serve`, `mcp`, `completion`; saída humana, JSON, Markdown, SARIF e HTML; `--fail-on` como portão de CI; cores que respeitam `NO_COLOR`.
- **Painel** em `teardown serve`: solte um arquivo em qualquer lugar da página, veja chegar ao vivo as análises feitas por outros clientes, leia o relatório com gráficos e tabelas, `Ctrl+K` para ir a qualquer lugar, temas claro e escuro, boa navegação por teclado, funciona offline.
- **Relatório HTML** com `analyze --html`: a mesma visão de relatório em um único arquivo autocontido, que abre do disco, offline, e não consegue fazer requisições de rede.
- **Servidor MCP** com cinco ferramentas (`analyze_file`, `list_strings`, `hash_file`, `entropy_profile`, `diff_files`), restrito aos diretórios que você permitir.

## Início rápido

Precisa de Go 1.24 ou mais novo e de mais nada. Clone o repositório e compile:

```bash
go build -o bin/teardown ./cmd/teardown        # no Windows o binário é bin\teardown.exe
./bin/teardown analyze examples/samples/upx-like.exe
```

Os exemplos em `examples/samples/` são arquivos minúsculos e inofensivos, gerados pelos construtores de fixtures deste repositório (`go run ./examples/gensamples`). Depois suba o painel e encha-o com os exemplos:

```bash
./bin/teardown serve                  # http://127.0.0.1:7777, deixe rodando
bash examples/upload-samples.sh       # em um segundo terminal. PowerShell: .\examples\upload-samples.ps1
```

## Uso

### Analisar um arquivo

<p align="center">
  <img src="docs/screenshots/cli.png" alt="Saída colorida do teardown analyze em upx-like.exe: barra de risco, hashes, sparkline de entropia, lista de endurecimento, tabela de seções e o primeiro achado" width="760">
</p>

O mesmo relatório em texto simples, que é o que você recebe em um pipe, em um log de CI ou com `--color never`:

```console
$ teardown analyze examples/samples/upx-like.exe
teardown  dev · static triage, the file was never executed

upx-like.exe
PE32+ executable for Windows (x86-64, console)  [64-bit, exe, upx, x86-64]
4.5 KiB (4,608 bytes) · type confidence high · analysed in 4 ms

RISK  ██████░░░░░░░░░░░░░░░░░░  27/100  MEDIUM
a triage aid for ordering a review queue, not a verdict

── Hashes
  md5      5e29588c93216679780cbf11abc9a3ae
  sha1     255349854c4bbf6f34f3ea5e95c458b74203f28b
  sha256   118218b6f8fdf30ae055ff248bf64fa3e155c3b4ec34aaadaae97b266fca3d21
  imphash  f9ade0aa18f660a34a4fa23392e21838

── Entropy  1.01 of 8.00 bits per byte
  ████░░░░░░░░░░░░░░░░░░░░░░░░░░░░  1.01
  ▄▂▂▁▁▁▂▁▁▁▁▁▁▁▁▁▁▁
  18 windows of 256 B; high bars suggest compressed or encrypted data

── Sections (5)
  name        virtual        raw  entropy           flags
  .text         512 B      512 B  ░░░░░░░░ 0.06     R-X
  .rdata        120 B      512 B  █░░░░░░░ 0.62     R--
  .data          32 B      512 B  ░░░░░░░░ 0.31     RW-
  UPX0      128.0 KiB        0 B  ░░░░░░░░ 0.00     RWX  writable and executable (RWX); section na…
  UPX1        2.0 KiB    2.0 KiB  ░░░░░░░░ 0.00     R-X  section name is typical of UPX

── Findings (5)
  [MEDIUM]   packing.upx  confidence high
      File is packed with UPX
      evidence: UPX markers detected (section names UPX0/UPX1 or the UPX! signature)
      limitation: UPX is a legitimate open-source packer that benign software also uses to shrink
                  binaries.
  [MEDIUM]   structure.rwx-section  confidence high
      Section is both writable and executable
      evidence: UPX0: flags RWX, raw size 0 B
      limitation: Describes the file layout, not run-time behaviour. Packers, self-extractors,
                  JIT-style loaders and some legacy toolchains legitimately use RWX sections.
  …
```

A saída acima está cortada (faltam endurecimento, importações, strings, mais três achados e as limitações), e o texto do programa é em inglês. `-v` acrescenta a conta do risco e toda a evidência. `--json` imprime o relatório inteiro como [`teardown.report/v1`](docs/api/schema.md), `--md` imprime Markdown, `--sarif` imprime SARIF e `--html` grava um relatório de arquivo único (abaixo):

```console
$ teardown analyze examples/samples/upx-like.exe --json
{
  "schema": "teardown.report/v1",
  "tool": { "name": "teardown", "version": "dev" },
  "file": { "name": "upx-like.exe", "size": 4608 },
  "type": { "id": "pe", "family": "executable", "label": "PE32+ executable for Windows (x86-64, console)", "confidence": "high", "tags": ["64-bit", "exe", "upx", "x86-64"] },
  "hashes": { "md5": "5e29588c93216679780cbf11abc9a3ae", "sha256": "118218b6f8fdf30a…" },
  "risk": { "score": 27, "label": "medium", "basis": [ … ] },
  "findings": [ { "id": "packing.upx", "severity": "medium", "category": "packing", "evidence": [ … ], "limitations": [ … ] }, … ],
  …
}
```

(Cortado e reindentado aqui; a saída real é maior e indentada linha a linha.) Todas as chaves estão na [referência do esquema](docs/api/schema.md).

### Barrar um build no CI

`--fail-on <severidade>` sai com status 3 quando existe um achado dessa severidade ou pior:

```console
$ teardown analyze examples/samples/upx-like.exe --fail-on high > /dev/null; echo $?
0
$ teardown analyze examples/samples/upx-like.exe --fail-on medium > /dev/null; echo $?
teardown analyze: --fail-on medium: 2 finding(s) at or above medium: packing.upx (medium), structure.rwx-section (medium)
3
```

Códigos de saída: `0` sucesso, `1` erro, `2` erro de uso, `3` limite atingido. Há scripts prontos: [`examples/ci-gate.sh`](examples/ci-gate.sh) e [`examples/ci-gate.ps1`](examples/ci-gate.ps1). Para painéis de varredura de código, `teardown analyze app.exe --sarif -o app.sarif` grava os achados como SARIF 2.1.0 ([detalhes](docs/cli.md#sarif), em inglês).

### Comparar dois arquivos

```console
$ teardown diff examples/samples/hello.exe examples/samples/upx-like.exe
teardown diff

a  hello.exe  2.0 KiB · PE32+ executable for Windows (x86-64, console) · risk 8
   sha256 6d3bd25d10c80d4c64ea8419f1bcf82dec72c8ea6c71cfe3be33a1a29d2f9fa5
b  upx-like.exe  4.5 KiB · PE32+ executable for Windows (x86-64, console) · risk 27
   sha256 118218b6f8fdf30ae055ff248bf64fa3e155c3b4ec34aaadaae97b266fca3d21

── Summary
  · SHA-256 differs
  · size 2048 -> 4608 bytes (+2560)
  · tags added: upx
  · import hash changed: the import table differs
  · 2 section(s) added: UPX0, UPX1
  · section .rdata entropy 2.33 -> 0.62
  · imports: +0 -3 functions
  · strings: +1 new, -5 gone
  · new finding packing.upx (medium)
  · new finding structure.rwx-section (medium)
  · new finding structure.suspicious-section (low)
  · finding gone privacy.pdb-path (low)
  · risk 8 (low) -> 27 (medium), +19
  …
```

(A saída continua com as seções adicionadas, os achados que apareceram ou sumiram, e as importações removidas e as strings novas.)

`strings`, `hash`, `serve`, `mcp` e `completion` estão na [referência de comandos](docs/cli.md).

### API HTTP

`teardown serve` serve o painel e uma API JSON em `127.0.0.1:7777`. Os relatórios ficam só na memória.

```console
$ curl -s -F file=@examples/samples/upx-like.exe http://127.0.0.1:7777/api/analyze
{"id":"an_afe16d7c12bb","report":{"schema":"teardown.report/v1","tool":{"name":"teardown","version":"dev"},"generatedAt":"2026-11-11T01:10:05.945Z","durationMs":1,"file":{"name":"upx-like.exe","size":4608},"type":{"id":"pe", …

$ curl -s http://127.0.0.1:7777/api/analyses
[{"id":"an_a4ebc5ea28de","name":"demo.apk","size":2018,"type":"apk","typeLabel":"Android package (APK)","risk":{"score":5,"label":"low"},"createdAt":"2026-11-11T01:10:06.004Z"}, …]

$ curl -s "http://127.0.0.1:7777/api/analyses/an_afe16d7c12bb/strings?category=api,plain&q=exit&limit=5"
{"total":1,"offset":0,"limit":5,"items":[{"value":"ExitProcess","offset":1594,"encoding":"ascii","category":"api","redacted":false,"kind":"system"}]}
```

`GET /api/events` é um fluxo de eventos enviados pelo servidor (SSE) que anuncia cada análise, inclusive as feitas por outros clientes:

```console
$ curl -sN http://127.0.0.1:7777/api/events
: stream open

event: analysis.started
data: {"id":"an_70a2454cafb6","name":"hello.exe","size":2048}

event: analysis.completed
data: {"id":"an_70a2454cafb6","name":"hello.exe","size":2048,"type":"pe","typeLabel":"PE32+ executable for Windows (x86-64, console)","risk":{"score":8,"label":"low"},"createdAt":"2026-11-11T01:10:07.473Z","durationMs":1}
```

No Windows PowerShell digite `curl.exe`, porque `curl` é um alias de `Invoke-WebRequest`. Rotas, erros, limites e o modelo de segurança: [docs/api/http.md](docs/api/http.md) (em inglês); legível por máquina: `GET /api/openapi.json` (OpenAPI 3.1).

### Painel

O `teardown serve` serve o painel em `http://127.0.0.1:7777`. Ele fala apenas com a API HTTP documentada, não carrega nada da rede e roda sob a Content-Security-Policy estrita do servidor. A página segue o layout Aurora: uma barra de navegação à esquerda, uma barra superior com o caminho de navegação, o botão de busca e o indicador ao vivo, uma barra secundária com o seletor de visão e as abas, cartões planos sob um brilho suave e uma fina barra de status, na paleta Prism Classic (Prism Daylight no tema claro).

<p align="center">
  <img src="docs/screenshots/home.png" alt="A página inicial do painel: um título, a área para soltar arquivos e a lista de análises recentes com selos de risco, tipos de arquivo, tamanhos e idades, da mais nova para a mais antiga" width="100%">
</p>

- **Início.** Solte um arquivo em qualquer lugar da página, clique na área de soltar, ou aperte `Ctrl+K` e escolha Upload. Cada envio mostra o progresso. Abaixo da área de soltar, a lista mostra as análises recentes (risco, nome, tipo, tamanho, idade, apagar com confirmação). Filtre por nome ou tipo, ordene por idade ou por risco com o seletor da barra secundária e veja a lista se atualizar ao vivo: um envio por `curl` feito em outro terminal aparece sem recarregar a página, primeiro como "Analysing" e depois com o seu risco.
- **Relatório** em `#/analysis/<id>`. O cabeçalho da página com nome do arquivo, tipo, tags e os botões JSON e Delete; o anel de risco e como a pontuação é calculada; cartões de resumo e hashes com botões de copiar; achados ordenados por severidade, com filtro de severidade, evidência e limitações; a lista de endurecimento; o perfil de entropia com o limite de empacotamento; seções com barras de entropia e flags de acesso; importações em um acordeão por biblioteca (as funções citadas por achados ficam destacadas); strings por categoria com busca e filtros (segredos continuam ocultos); detalhes do formato e limitações. As abas da barra secundária levam a cada seção, mostram quantos itens ela tem e acompanham a rolagem, e os selos à direita da barra trazem o risco, o tamanho e o tipo. Todo gráfico tem o alternador Gráfico/Tabela.
- **Paleta de comandos.** `Ctrl+K` abre uma análise recente, pula para uma parte do relatório, copia um hash, envia um arquivo ou troca o tema.

<p align="center">
  <img src="docs/screenshots/charts.png" alt="O perfil de entropia de dropper.bin com a linha do limite de empacotamento 7,2 e a tabela de seções com barras de entropia, flags de acesso e os motivos pelos quais uma seção foi sinalizada" width="100%">
</p>

O layout foi conferido em 360, 768, 1440 e 1920 px de largura, nos temas escuro e claro, com movimento reduzido e com o teclado.

<p align="center">
  <img src="docs/screenshots/mobile.png" alt="O mesmo relatório em um celular: as abas das seções rolam para o lado sob a barra superior, a barra de navegação virou uma barra no rodapé e o cabeçalho, o anel de risco e os cartões ficam empilhados em uma coluna" width="320">
</p>

### Relatório HTML de arquivo único

```console
$ teardown analyze examples/samples/upx-like.exe --html report.html
wrote report.html (risk 27/100 medium, 5 findings)
```

O `report.html` (cerca de 240 KB) é a página de relatório do painel em um só arquivo, com a mesma barra de navegação, as mesmas barras e as mesmas abas (aqui simples links `#fragmento`): estilos, scripts e o próprio relatório vão embutidos, então ele abre do disco, offline, e pode ser anexado a um chamado ou e-mail.

<p align="center">
  <img src="docs/screenshots/export-light.png" alt="O relatório HTML exportado de upx-like.exe no tema claro: o mesmo layout do painel, com um botão Copy JSON no cabeçalho da página" width="100%">
</p>

- O relatório fica em uma ilha JSON inerte em que `<`, `>`, `&`, U+2028, U+2029 e caracteres de formatação invisíveis são escapados, então um nome de arquivo ou string hostil não consegue fechá-la; a visão mostra tudo como texto.
- Uma tag `<meta>` de Content-Security-Policy permite apenas o script e o estilo da própria página (por hash) e imagens `data:`, de modo que nem um bug na página conseguiria fazer uma requisição de rede.
- Com scripts desligados, o `<noscript>` mostra um resumo simples e legível. Testes cobrem os três pontos.

### MCP para agentes de IA

`teardown mcp` fala o Model Context Protocol por stdio. Só é possível ler arquivos dentro dos diretórios de `--root`; links simbólicos que escapam, diretórios e dispositivos são recusados.

| Ferramenta | O que devolve |
|---|---|
| `analyze_file` | O relatório (tipo, hashes, entropia, seções, importações, endurecimento, achados, risco), com um nível de `detail` |
| `list_strings` | Strings classificadas com deslocamentos, filtráveis por categoria e texto, paginadas |
| `hash_file` | MD5, SHA-1, SHA-256 e o hash de importação de PE |
| `entropy_profile` | Entropia total e até 512 janelas |
| `diff_files` | O que mudou entre dois arquivos |

Uma troca real, alimentada por [`examples/mcp-session.jsonl`](examples/mcp-session.jsonl) (respostas encurtadas; os caminhos nas mensagens foram omitidos):

```console
$ teardown mcp --root examples/samples < examples/mcp-session.jsonl
{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"teardown","title":"teardown static triage","version":"dev"}, …}}
{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"analyze_file", …}, {"name":"list_strings", …}, {"name":"hash_file", …}, {"name":"entropy_profile", …}, {"name":"diff_files", …}]}}
{"jsonrpc":"2.0","id":5,"result":{"content":[{"type":"text","text":"path \"../etc/passwd\" is outside the allowed roots; only files inside … can be analysed"}],"isError":true}}
…
```

A configuração para Claude Desktop e Claude Code e a transcrição completa estão no [guia MCP](docs/mcp.md) (em inglês).

## Arquitetura

```mermaid
flowchart LR
  CLI["CLI"] --> AN
  HTTP["API HTTP + painel"] --> AN
  MCP["MCP via stdio"] --> AN
  AN["analyze: um só pipeline"] --> SN["sniff: tipo"]
  AN --> HS["hash + entropia + strings: uma passada"]
  AN --> FM["parsers de formato: pe elf macho go archive asar wasm gguf"]
  AN --> RU["rules: achados + risco"]
  SN --> RP[("relatório: teardown.report/v1")]
  HS --> RP
  FM --> RP
  RU --> RP
  RP --> RN["render: texto, Markdown, HTML"]
  RP --> UI["visão de relatório: painel e relatório HTML"]
```

Um pipeline produz um contrato de dados, e cada porta de entrada é uma casca fina em volta dos dois. Mais em [docs/architecture.md](docs/architecture.md) (em inglês).

## Estrutura do projeto

```text
cmd/teardown/           ponto de entrada
internal/analyze/       o pipeline: sniff, hashing em uma passada, parser, regras, relatório
internal/report/        o contrato teardown.report/v1 (pacote folha)
internal/sniff/         detecção de tipo por bytes mágicos e estrutura
internal/format/*/      um parser por formato: pe elf macho goinfo archive asar wasm gguf
internal/rules/         motor de achados e pontuação de risco (docs/rules.md é gerado a partir dele)
internal/render/        saída de terminal, Markdown e HTML
internal/server/        API HTTP, middleware de segurança, eventos SSE, documento OpenAPI
internal/mcp/           servidor MCP via stdio
internal/cli/           subcomandos, flags, autocompletar
web/                    o painel e o kit de interface Aurora (embutidos com go:embed), a visão de relatório compartilhada
docs/                   arquitetura, referência de comandos, API HTTP, esquema, regras, guia MCP
examples/               amostras geradas, scripts de portão de CI e de envio, uma sessão MCP
testdata/               relatório de amostra de referência (golden)
```

## Configuração

| Opção | Onde | Padrão | Significado |
|---|---|---|---|
| `--addr` | `serve` | `127.0.0.1:7777` | Endereço de escuta; qualquer coisa fora do loopback gera um aviso |
| `--max-upload` | `serve` | `256MiB` | Maior envio aceito |
| `--keep` | `serve` | `50` | Análises mantidas em memória, as mais antigas saem primeiro (no máximo 10000) |
| `--root` | `mcp` | diretório atual | Diretório de onde arquivos podem ser lidos; repetível |
| `--min-string` | `analyze` | `5` | Tamanho mínimo de string |
| `--max-strings` | `analyze` | `2000` | Strings mantidas no relatório |
| `--timeout` | `analyze` | `1m` | Desiste depois desse tempo |
| `--color`, `--ascii`, `--width` | `analyze`, `strings`, `hash`, `diff` | `auto` | Saída no terminal |
| `NO_COLOR` | ambiente | vazio | Qualquer valor não vazio desliga as cores |
| `TEARDOWN_ASCII` | ambiente | vazio | Qualquer valor não vazio troca as barras por ASCII |

## Segurança

- **O alvo nunca é executado**, carregado, avaliado ou descompactado além de pequenos metadados limitados.
- **Limites em toda parte.** Toda contagem, deslocamento e tamanho lido de um arquivo é conferido contra o tamanho do arquivo antes de qualquer alocação, toda lista tem teto, todo laço longo respeita o contexto, e uma análise tem prazo de 60 segundos. Uma falha de parser vira um achado e o resto do relatório sobrevive.
- **O servidor é para você, na sua máquina.** Escuta em loopback por padrão e só responde a cabeçalhos `Host` de loopback (defesa contra DNS rebinding), recusa `POST` e `DELETE` de outra origem, não envia cabeçalhos CORS e usa uma Content-Security-Policy estrita. Os envios são gravados em streaming em um diretório privado com nomes aleatórios, limitados ao byte e apagados logo após a análise. Não há autenticação nem TLS: não exponha a uma rede em que você não confia. [Detalhes](docs/api/http.md#security-model).
- **O MCP é confinado.** Os arquivos são abertos por `os.Root` apenas dentro dos diretórios permitidos; links simbólicos que escapam, diretórios e dispositivos são recusados.
- **Segredos continuam ocultos** em toda saída: terminal, JSON, Markdown, a API, o MCP e o relatório HTML.
- **Abrir um relatório é seguro.** O texto vindo do arquivo analisado é mostrado como texto, nunca como marcação. O relatório HTML é um arquivo único e offline, com uma Content-Security-Policy que não permite acesso à rede, e o JSON embutido não pode ser fechado por nomes ou strings hostis.
- Sem telemetria, sem acesso à rede em tempo de execução, sem módulos de terceiros.

Vulnerabilidades: veja [SECURITY.md](SECURITY.md).

### Limitações

O teardown é uma primeira olhada, não um sandbox nem um antivírus. Ele não desmonta, não emula e não desempacota (um disassembler pequeno para o código como evidência está no roteiro). Empacotadores e protetores escondem código e importações da análise estática; importações resolvidas em tempo de execução ficam invisíveis. Os achados são heurísticas: cada um diz como pode ser um falso positivo. Assinaturas Authenticode e de código são detectadas, não verificadas. As permissões do Android são lidas do manifesto de forma heurística. PDF, SQLite, safetensors, imagens e formatos de compressão são reconhecidos, mas não interpretados. Os relatórios ficam na memória e somem quando o servidor para.

## Testes

```bash
go test ./...                   # offline, cerca de 25 segundos
go test -race -p 1 ./...        # detector de corridas, um pacote por vez (precisa de cgo; o CI roda em Linux, macOS e Windows; leva alguns minutos)
make fuzz FUZZTIME=20s          # cada alvo de fuzzing nativo, 20 s cada
```

576 funções de teste (cerca de 2.800 casos com os subtestes) em 25 pacotes, mais 18 alvos de fuzzing. A suíte gera as próprias fixtures em código (sem binários de terceiros), roda uma varredura de "nunca entra em pânico" em cada parser (todo tamanho de prefixo, bytes corrompidos), faz fuzzing do sniffer e de cada parser, testa a camada HTTP com `httptest` e o MCP por pipes em memória (inclusive tentativas de escapar da raiz e por links simbólicos), fixa o contrato do relatório com um arquivo de referência e confere os arquivos do painel e o relatório HTML (nomes e strings hostis, U+2028, hashes da Content-Security-Policy, sem URLs externas, tamanho).

## Roteiro

**Planejado, pronto até 15 de novembro de 2026: código como evidência.** Hoje o teardown mostra o que achou (nomes de APIs, strings, flags de seção). A próxima versão mostra o código por trás de cada achado, para quem desenvolve:

- um hexdump, com offsets, dos bytes que causaram o achado;
- os pontos onde as importações suspeitas são chamadas, com o disassembly ao redor, por exemplo onde `VirtualAllocEx`, `WriteProcessMemory` e `CreateRemoteThread` são chamadas (um disassembler x86 e x86-64 próprio e pequeno, conferido contra o do toolchain do Go);
- as linhas de código-fonte correspondentes para scripts dentro de arquivos ASAR e ZIP;
- tudo isso por novos comandos do CLI (`disasm`, `xrefs`, `hexdump`), no relatório, no painel e em ferramentas MCP que agentes podem chamar.

Continuará não sendo um decompilador, e o ARM64 vem depois.

Outras ideias, em ordem aproximada, não promessas:

- Parsers para safetensors, SQLite e a estrutura de PDF; metadados de .NET e detalhes de classes Java.
- Verificar assinaturas Authenticode e de código do macOS em vez de só detectá-las.
- Um armazenamento persistente para o servidor (hoje só memória) e uma tela de comparação no painel.

## Contribuindo

Pequeno e sem dependências é o ponto. Leia o [CONTRIBUTING.md](CONTRIBUTING.md) (em inglês) para configurar o ambiente, ver as verificações a rodar e saber como adicionar um parser ou uma regra. Os commits seguem [Conventional Commits](https://www.conventionalcommits.org/pt-br/).

## Licença

[MIT](LICENSE) © 2026 q6r.

## Créditos

O teardown é inspirado no [REA](https://github.com/morluto/rea), que mostrou como achados com evidência e limitações são úteis quando um agente de IA pode pedi-los por MCP. O teardown é um projeto independente, de sala limpa (clean-room): não é afiliado ao REA nem derivado dele, e tem um escopo bem mais estreito (só triagem estática, sem desmontador nem decompilador). A comparação está em [docs/inspired-by-rea.md](docs/inspired-by-rea.md) (em inglês). O painel é construído sobre o kit de interface Aurora (uma folha de estilo e dois scripts: zero dependências, MIT, parte deste repositório em `web/`).
