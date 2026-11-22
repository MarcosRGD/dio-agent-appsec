# Lab: login vulnerável e login corrigido

Código de laboratório, escrito para este repositório. Não é código de produção e não deve ser publicado em servidor exposto. Serve para uma coisa: dar ao agente um caso real sobre o qual analisar, e uma prova de que a correção funciona.

## Arquivos

| Arquivo | O que é |
|---------|---------|
| `app.py` | login com **injeção de SQL** (CWE-89): a consulta é montada com `f-string` e a senha é comparada em texto claro |
| `app_corrigido.py` | mesma função, com consulta parametrizada, hash PBKDF2-SHA256 com salt, comparação de tempo constante, conexão somente leitura e mensagem genérica |
| `test_login.py` | teste de regressão: documenta que o vulnerável é invadido e prova que o corrigido resiste |
| `labdata/` | bancos descartáveis, criados pelo teste (fora do Git) |

## Rodar

```
python3 lab/test_login.py
```

Não depende de nada além da biblioteca padrão do Python 3.10+. O teste cria os dois bancos em `lab/labdata/`, roda os ataques e apaga/recria a cada execução.

Saída esperada no fim:

```
N/N verificações passaram
RESULTADO: TUDO OK — injeção de SQL mitigada, senha com hash, sem enumeração por tempo
```

## O que o teste prova

Seção 1 roda contra `app.py` e **espera ser invadido**: `admin' --` e `' OR 1=1 --` entram. Isso é a evidência de que a falha é real, não teórica.

Seção 2 roda os mesmos payloads contra `app_corrigido.py` e exige negação. Também verifica que a senha não está em claro no banco, que a conexão do login não escreve, que a tabela ficou intacta e que o tempo de resposta para usuário inexistente é próximo do tempo para usuário existente (evita enumerar contas por cronômetro).

## Por que manter o código vulnerável no repositório

Porque o desafio acontece em duas etapas: analisar o vulnerável e depois provar a correção. Guardar os dois permite reexecutar a análise a qualquer momento e comparar com uma resposta de chat genérica, que descreveria a falha mas não teria teste passando.
