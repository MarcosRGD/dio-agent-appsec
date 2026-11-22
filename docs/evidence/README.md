# Evidências

Saída real das execuções citadas no README e no relatório de análise. Nada aqui é exemplo inventado: cada arquivo é o que o comando produziu na máquina de quem rodou.

| Arquivo | O que é | Como reproduzir |
|---------|---------|-----------------|
| [`analise-sqli-app.md`](analise-sqli-app.md) | Relatório completo de `lab/app.py` no formato da skill `vulnerability-analysis` (contexto, achado, risco, exploração, adversário, correção, verificação) | leitura; o número de cada nota está justificado com a evidência correspondente |
| [`test-login-2026-11-22.txt`](test-login-2026-11-22.txt) | Saída literal de `python3 lab/test_login.py`: 19/19 verificações, exit 0 | `python3 lab/test_login.py` |

## Prints

Capturas do repositório publicado, feitas em navegador sem sessão iniciada (é o que qualquer pessoa vê):

| Print | O que mostra |
|-------|--------------|
| [`prints/01-repo-readme-appsec.png`](prints/01-repo-readme-appsec.png) | A seção "Especialização em segurança de aplicação" do README, com as 6 etapas e o ponteiro para `lab/` |
| [`prints/02-teste-19-de-19.png`](prints/02-teste-19-de-19.png) | O arquivo `test-login-2026-11-22.txt` aberto no GitHub, de onde sai a linha `19/19 verificacoes passaram` e `# exit=0` |

## Como ler a saída do teste

- **Seção 1 — código vulnerável (esperado: ser invadido).** Cada linha `[OK]` aqui significa que o ataque **funcionou**. Seção toda verde é o retrato do problema, não da solução.
- **Seção 2 — código corrigido (esperado: resistir).** Aqui `[OK]` significa que o ataque foi barrado e que a defesa é verificável: hash com salt, conexão somente leitura, tempo de resposta parecido para usuário inexistente.

Se a seção 1 ficar vermelha, o ambiente mudou e o material de estudo não representa mais o problema. Se a seção 2 ficar vermelha, a correção quebrou.

## Ambiente da execução registrada

Linux 7.3.4, Python 3.12.11, apenas biblioteca padrão. Os bancos usados pelo teste são descartáveis e ficam em `lab/labdata/`, fora do Git.
