# Análise de vulnerabilidade — `lab/app.py`

Relatório produzido pelo DIO Agent com a skill `vulnerability-analysis`.
Alvo: `lab/app.py` (login com injeção de SQL), corrigido em `lab/app_corrigido.py`.
Evidência de execução: [`test-login-2026-11-22.txt`](test-login-2026-11-22.txt).

## CONTEXTO

| Pergunta | Resposta |
|----------|----------|
| O que é / onde roda | script Python de login, SQLite local, executado só na máquina do próprio autor |
| Quem alcança | ninguém de fora: o teste roda em `127.0.0.1` contra um banco descartável em `lab/labdata/` |
| Que dado toca | credencial de usuário (usuário e senha) e o papel (`user` / `admin`) |
| Alcance autorizado | código do próprio autor, laboratório local. Nenhum teste contra sistema de terceiro |
| O que existe em volta | nada: sem WAF, sem limitação de tentativas, sem permissão restrita no banco |

Esse contexto importa para a nota. O mesmo código publicado numa API pública com banco de produção teria outra probabilidade — e outra severidade.

## ACHADO

- **Fluxo:** recebe usuário e senha e decide se a pessoa entra, consultando a tabela `usuarios`.
- **Entrada não confiável:** os dois campos do formulário, usados diretamente na montagem do texto da consulta (`lab/app.py`, linha 7).
- **Classe:** CWE-89 (injeção de SQL), OWASP A03:2021 (Injection).
- **Causa:** a consulta é montada por concatenação — o que a pessoa digita passa a ser parte da instrução SQL, não dado.

## RISCO

| | Nota | Justificativa |
|---|---|---|
| **Impacto** | 4/5 | Entrar como qualquer usuário, inclusive o administrador, e ler a tabela inteira. Evidência: `admin' --` e `' OR 1=1 --` devolvem `Acesso Permitido!`; o `UNION` devolve 2 linhas com `roles=['user', 'admin']` e as senhas em claro. Não é 5 porque não há execução de comando nem acesso ao host — o efeito morre no banco. |
| **Probabilidade** | 5/5 | Exploração trivial: um campo de texto, sem autenticação prévia e sem ferramenta especial. Evidência: os três payloads de brinquedo do próprio teste já passam. |
| **Severidade** | **Crítica** | Impacto 4 × Probabilidade 5 na rubrica. |

## EXPLORAÇÃO

1. O atacante digita no campo de usuário algo que fecha a aspa simples e comenta o resto da instrução.
2. A consulta que o banco recebe deixa de ser "usuário igual a X" e passa a ser "usuário igual a '' ou qualquer coisa", e o trecho da senha fica comentado.
3. A consulta devolve a primeira linha da tabela — que é a de administrador — e o login é concedido sem saber a senha.
4. Variante de leitura: em vez de só entrar, o atacante encaixa uma segunda consulta que devolve colunas da tabela inteira. O resultado vai para a tela junto com a resposta de sucesso.
5. O que **não** funciona aqui: empilhar dois comandos separados por ponto e vírgula. O driver `sqlite3` recusa mais de um comando por chamada — isso é limite do driver, **não** defesa do código, e não vale como mitigação.

## ADVERSÁRIO (MITRE ATT&CK)

- **T1190 — Exploit Public-Facing Application:** é exatamente o caso de usar uma falha de entrada para alcançar o sistema.
- **T1078 — Valid Accounts:** depois do bypass, o atacante opera com uma conta legítima (a de administrador). É por isso que log de login não basta para detectar: a sessão parece normal.

ATT&CK descreve comportamento, não a falha. A falha está no código (CWE-89); o ATT&CK diz como alguém a usa.

## CORREÇÃO

- **Principal:** consulta parametrizada — o SQL vai com marcador (`?`) e o valor viaja separado, então o banco nunca interpreta a entrada como instrução. É a correção que fecha a classe inteira, não só os payloads conhecidos.
- **Em profundidade:** conexão somente leitura (o caminho de login não precisa escrever), mensagem de erro genérica e, fora do código, usuário de banco com permissão mínima.
- **Fora deste código:** limitação de tentativas e bloqueio progressivo (camada de rede ou gateway), gestão de sessão com cookie `HttpOnly; Secure; SameSite=Strict`, e monitoramento de falhas de login em sequência.
- **O que a correção não resolve:** se o atacante já tem a senha, ele entra — parametrização não substitui autenticação forte nem limite de tentativas.

## Achado secundário — senha em claro

`lab/app.py` compara a senha digitada com o valor guardado direto no banco. Classe provável: CWE-256 (armazenamento de credencial sem proteção), com CWE-916 associado (hash com custo insuficiente) quando existe hash fraco.

- **Impacto 4/5:** qualquer cópia do banco entrega todas as senhas — e as pessoas reaproveitam senha em outros serviços.
- **Probabilidade 3/5:** depende de já ter acesso ao banco (backup vazado, leitura indevida).
- **Severidade:** Alta.
- **Correção:** hash com salt e custo (`bcrypt`, `argon2id`, `scrypt` ou PBKDF2 com muitas iterações) e comparação de tempo constante. No `lab/app_corrigido.py` foi usado PBKDF2-SHA256 com 600.000 iterações, porque só usa a biblioteca padrão. Senha já existente em claro precisa ser trocada, não apenas re-hasheada sem avisar o usuário.

## VERIFICAÇÃO

O teste que prova a correção está em `lab/test_login.py` e roda em qualquer máquina com Python 3.10+:

```
python3 lab/test_login.py
```

Ele falha se a correção não estiver no lugar: a seção 1 exige que o código vulnerável **seja** invadido, e a seção 2 exige que o corrigido **resista** aos mesmos três payloads, rejeite entrada inválida, guarde hash com salt e não permita escrita pela conexão de leitura. Resultado registrado: **19/19 verificações**, exit 0.
