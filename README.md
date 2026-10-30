# postman-hunter

**postman-hunter** é um rastreador de segredos/credenciais focado em **coleções
públicas do Postman**. Ele combina:

- o **catálogo de padrões de segredos** do `secret-hunter` (AWS, GCP, Azure,
  GitHub, OpenAI, Stripe, JWT, chaves privadas, etc.);
- a **lógica de reconhecimento da rede pública do Postman** (busca de coleções
  por domínio, coleta de workspaces e coleções, extração de requests,
  variáveis, cabeçalhos e corpos);
- a **validação opcional por IA** (`verboo`, `openrouter` ou `ollama`) para
  classificar cada candidato (gravidade, pontuação, impacto, correção).

Em resumo: é uma versão do `secret-hunter` voltada para o que aparece em
coleções Postman públicas de um domínio e de seus subdomínios.

---

## Índice

- [O que ele faz](#o-que-ele-faz)
- [Como funciona](#como-funciona)
- [Requisitos](#requisitos)
- [Instalação](#instalação)
- [Uso](#uso)
- [Provedores de IA](#provedores-de-ia)
- [Chave da API do Postman](#chave-da-api-do-postman)
- [Referência de opções](#referência-de-opções)
- [Formato do relatório](#formato-do-relatório)
- [Segurança e uso autorizado](#segurança-e-uso-autorizado)

---

## O que ele faz

1. **Aceita domínios** — por argumento posicional ou por um arquivo `.txt`
   (`--domains-file`), com um domínio por linha.
2. **Resolve os subdomínios** de cada domínio de forma **passiva** via
   Certificate Transparency (crt.sh), em HTTP — sem enumeração DNS, então
   funciona atrás de uma VPN como a Mullvad.
3. **Busca na rede pública do Postman** cada domínio/subdomínio:
   - usa o proxy de busca público do Postman (funciona sem chave);
   - se uma **chave da API do Postman** for fornecida, usa também a API
     oficial de busca para obter mais resultados;
   - coleta workspaces encontrados e suas coleções.
4. **Baixa e achata cada coleção** em texto (requests, variáveis, cabeçalhos,
   corpos, auth, URLs) e aplica o **catálogo de padrões** do `secret-hunter`.
5. **Valida/classifica** (opcional) cada candidato com um LLM — Verboo,
   OpenRouter ou Ollama — com o mesmo fluxo do `secret-hunter`.
6. **Gera relatório** em JSON e um resumo legível no terminal.

---

## Como funciona

O fluxo é:

```
domínios (arquivo ou argumento)
   │
   ├─ resolve subdomínios (crt.sh, passivo, HTTP)
   │
   └─ para cada domínio/subdomínio:
         busca no Postman (proxy público + API oficial, se houver chave)
            │
            ├─ coleta entidades (coleções, requests, workspaces)
            └─ baixa coleções → achata em texto
                     │
                     └─ extrai segredos (catálogo secret-hunter)
                              │
                              └─ (opcional) classifica com LLM
                                       │
                                       └─ relatório JSON + texto
```

Os candidatos são deduplicados por (tipo, valor) e, se um provedor de IA for
configurado, cada um recebe uma classificação. A descoberta de subdomínios é
**passiva** (logs de certificados), então não há varredura DNS — o que mantém
a ferramenta confiável atrás da Mullvad.

---

## Requisitos

- Python 3.10 ou superior.
- A biblioteca `requests`.
- O pacote `secret-hunter` disponível em `/opt/secret-hunter` (por padrão). O
  caminho pode ser sobrescrito pela variável `SECRET_HUNTER_PATH`.

---

## Instalação

```bash
pip install -r /opt/postman-hunter/requirements.txt
```

O `postman-hunter` importa o catálogo de padrões, provedores e classificador
do `secret-hunter`. Se o `secret-hunter` estiver em outro local:

```bash
export SECRET_HUNTER_PATH="/caminho/para/secret-hunter"
```

---

## Uso

Buscar um domínio direto na rede pública do Postman:

```bash
python3 postman-hunter.py example.com
```

A partir de um arquivo de domínios (resolve subdomínios antes):

```bash
cat > dominios.txt <<'EOF'
example.com
other.org
EOF

python3 postman-hunter.py --domains-file dominios.txt
```

Com chave da API do Postman (mais resultados) e sem resolver subdomínios:

```bash
python3 postman-hunter.py --domains-file dominios.txt \
  --postman-api-key "PMAK-xxxx" --no-subdomains
```

Com validação por IA (Ollama local, por padrão):

```bash
python3 postman-hunter.py example.com --provider ollama
```

Salvar o relatório em JSON:

```bash
python3 postman-hunter.py example.com -o resultado.json --quiet
```

---

## Provedores de IA

A validação usa o mesmo cliente OpenAI-compatível do `secret-hunter`. Os três
provedores suportados são **Verboo**, **OpenRouter** e **Ollama**.

```bash
# Ollama (local)
python3 postman-hunter.py example.com --provider ollama

# OpenRouter
export OPENROUTER_API_KEY="sk-or-v1-..."
python3 postman-hunter.py example.com --provider openrouter

# Verboo (endpoint/configurável)
export VERBOO_BASE_URL="https://seu-endpoint-verboo/v1"
export VERBOO_API_KEY="sua-chave"
export VERBOO_MODEL="seu-modelo"
python3 postman-hunter.py example.com --provider verboo
```

Também é possível usar `SECRET_HUNTER_PROVIDER`, `SECRET_HUNTER_BASE_URL`,
`SECRET_HUNTER_API_KEY`, `SECRET_HUNTER_MODEL` e `SECRET_HUNTER_TIMEOUT`, como
no `secret-hunter`.

---

## Chave da API do Postman

A chave é opcional: sem ela, o `postman-hunter` usa apenas o proxy de busca
público do Postman. Com ela, também consulta a API oficial de busca, que
costuma devolver mais coleções/workspaces.

```bash
# Via flag
python3 postman-hunter.py example.com --postman-api-key "PMAK-..."

# Via variável de ambiente
export POSTMAN_API_KEY="PMAK-..."
python3 postman-hunter.py example.com
```

---

## Referência de opções

| Opção | Padrão | Descrição |
|-------|--------|-----------|
| `targets` (posicional) | — | Domínio(s) ou URL(s) a buscar no Postman. |
| `--domains-file` | — | Arquivo `.txt` com um domínio por linha; subdomínios são resolvidos antes da busca. |
| `--no-subdomains` | `false` | Não resolve subdomínios para os domínios do arquivo. |
| `--postman-api-key` | — | Chave da API do Postman (ou `POSTMAN_API_KEY`). |
| `--provider` | env/`ollama` | `verboo`, `openrouter` ou `ollama`. |
| `--base-url` | — | Sobrescreve a base URL do provedor de IA. |
| `--api-key` | — | Sobrescreve a chave do provedor de IA. |
| `--model` | — | Sobrescreve o modelo de IA. |
| `--no-llm` | `false` | Pula a validação por IA (somente regex). |
| `--mask-secrets` | `false` | Mascara os segredos no relatório e antes do envio ao LLM. |
| `--max-collections` | `50` | Máximo de coleções a baixar e varrer. |
| `--timeout` | `15` | Timeout por requisição (segundos). |
| `--concurrency` | `8` | Requisições paralelas. |
| `--proxy` | — | Proxy HTTP(S) para todas as requisições. |
| `-o` / `--output` | — | Grava o relatório JSON neste caminho. |
| `--quiet` | `false` | Suprime o resumo no terminal. |

---

## Formato do relatório

O JSON contém metadados e a lista de `findings`:

```json
{
  "tool": "postman-hunter",
  "version": "1.0.0",
  "generated_at": "2026-10-26T09:00:00+00:00",
  "targets": ["example.com", "api.example.com"],
  "postman_api_key_used": false,
  "provider": "ollama",
  "subdomains_discovered": {
    "example.com": ["api.example.com", "www.example.com"]
  },
  "postman_entities_found": 3,
  "collections_scanned": 1,
  "requests_scanned": 2,
  "candidates_found": 3,
  "findings": [
    {
      "type": "AWS Access Key",
      "category": "api_key",
      "value": "AKIA7X4QZR2M9KLPT5V8",
      "entropy": 4.12,
      "source": "postman-collection:2664f86d-f802-463a-b731-b68d6821464b::Payments / Capture a Payment",
      "collection": "Stripe API Demos",
      "collection_id": "2664f86d-f802-463a-b731-b68d6821464b",
      "collection_url": "https://www.postman.com/stripe-developers/collection/2664f86d-f802-463a-b731-b68d6821464b",
      "request": "Payments / Capture a Payment",
      "workspace": "Stripe Developers",
      "locations": [
        {
          "source": "postman-collection:2664f86d-f802-463a-b731-b68d6821464b::Payments / Capture a Payment",
          "collection": "Stripe API Demos",
          "collection_id": "2664f86d-f802-463a-b731-b68d6821464b",
          "collection_url": "https://www.postman.com/stripe-developers/collection/2664f86d-f802-463a-b731-b68d6821464b",
          "request": "Payments / Capture a Payment",
          "workspace": "Stripe Developers"
        }
      ],
      "snippet": "key=api_key value=AKIA7X4QZR2M9KLPT5V8N3",
      "analysis": {
        "criticality": "High",
        "score": 8.5,
        "reportable": true,
        "impact": "...",
        "remediation": "...",
        "cwe": "CWE-798",
        "explanation": "..."
      }
    }
  ]
}
```

### De onde veio cada chave

Cada `finding` identifica **onde** o segredo foi encontrado:

- `source` — identificador da origem: `postman-collection:<uuid>::<caminho do request>`
  para achados dentro de uma coleção, ou `postman-<tipo>:<id>` para achados nos
  metadados da busca (nome/URL de coleções e workspaces).
- `collection` / `collection_id` / `workspace` — a coleção (nome e UUID) e o
  workspace de onde veio o segredo.
- `request` — o request (ou pasta/request) dentro da coleção onde o valor
  apareceu. É `null` quando o segredo está nas variáveis/auth da coleção.
- `collection_url` — link público abrível no Postman
  (`https://www.postman.com/<workspace>/collection/<uuid>`), quando o slug do
  workspace é conhecido; caso contrário fica vazio (nunca um link quebrado).
- `locations` — todas as origens onde o mesmo valor (tipo+valor) foi visto,
  útil quando a mesma chave aparece em várias coleções/requests.

Por padrão, o valor do segredo aparece **em texto claro** (campo `value`). Use
`--mask-secrets` para mascarar.

---

## Segurança e uso autorizado

- **Use apenas em alvos que você possui ou para os quais tem autorização
  explícita.** Este é um scanner de segurança; a execução não autorizada é
  ilegal em muitas jurisdições.
- A busca na rede pública do Postman é somente leitura. A chave da API do
  Postman, quando fornecida, é usada apenas para consultas de busca.
- Se você usar um provedor de IA remoto (Verboo/OpenRouter), os valores dos
  segredos são enviados ao provedor por padrão. Use `--mask-secrets` para
  mascarar antes do envio, ou `--provider ollama` / `--no-llm` para manter
  tudo local.
- Como os segredos aparecem em texto claro por padrão, trate o relatório JSON
  com cuidado: ele contém credenciais reais.

---

## Sobrescrever endpoints (para testes / self-hosted)

Os endpoints usados podem ser sobrescritos por variáveis de ambiente:

| Variável | Padrão |
|----------|--------|
| `POSTMAN_SEARCH_PROXY` | `https://www.postman.com/_api/ws/proxy` |
| `POSTMAN_WORKSPACE_URL` | `https://www.postman.com/_api/workspace/{wid}` |
| `POSTMAN_COLLECTION_URL` | `https://www.postman.com/_api/collection/{cid}?populate=true` |
| `POSTMAN_COLLECTION_URL_NO_POPULATE` | `https://www.postman.com/_api/collection/{cid}` |
| `POSTMAN_API_SEARCH_URL` | `https://api.getpostman.com/search?query={query}&type={type}` |
| `POSTMAN_PUBLIC_BASE` | `https://www.postman.com` (base dos links no relatório) |
| `SECRET_HUNTER_CRT_SH_URL` | `https://crt.sh/?q=%25.{domain}&output=json` |

Os placeholders `{wid}`, `{cid}`, `{query}` e `{type}` são substituídos na
hora da chamada.
