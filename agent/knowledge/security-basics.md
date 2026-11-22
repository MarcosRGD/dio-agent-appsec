# Fundamentos de segurança

Este arquivo dá ao DIO Agent o vocabulário e os critérios que ele usa quando o assunto é segurança. Ele não substitui a skill `vulnerability-analysis`: a skill diz **como** conduzir a análise, este arquivo diz **o que** as palavras significam.

Leia este arquivo antes de opinar sobre código, configuração ou infraestrutura com problema de segurança.

## Os quatro conceitos que as pessoas confundem

Quase toda conversa de segurança desanda porque alguém mistura estes conceitos. Separe-os sempre.

**Ativo** — o que tem valor e precisa ser protegido. Um banco de dados de clientes, uma conta de administrador, uma chave de API, a reputação da empresa, o serviço no ar.

**Vulnerabilidade** — uma fraqueza no software, na configuração ou no processo que permite a alguém tirar o ativo do estado esperado. É uma característica do sistema, não de quem ataca. Exemplo: uma consulta SQL montada juntando texto com o que a pessoa digitou.

**Ameaça** — quem ou o que pode explorar aquela fraqueza. Um atacante com acesso à internet, um usuário autenticado insatisfeito, um script automatizado que varre a internet em busca de alvos, um erro de operação.

**Risco** — a combinação de probabilidade e impacto **naquele contexto**. É o que decide prioridade. A mesma vulnerabilidade tem risco diferente conforme onde o sistema roda, que dado ela toca e quais controles existem em volta.

Exemplo único, costurando os quatro: um formulário de login (ativo: as contas de usuário) monta a consulta SQL por concatenação de texto (vulnerabilidade: injeção de SQL) e está publicado na internet sem limitação de tentativas (ameaça: qualquer um, com script pronto). O risco é alto porque qualquer pessoa chega nele, a exploração é simples e o resultado é entrar como outro usuário.

A frase que resume a diferença: **vulnerabilidade é a fechadura fraca, ameaça é quem gira o trinco, risco é a chance de isso acontecer com o que você tem a perder.**

## A tríade CIA (confidencialidade, integridade e disponibilidade)

Todo impacto de segurança cai em uma destas três (ou nas três):

- **Confidencialidade** — só quem deve ver, vê. Quebra quando dado vaza: dump de banco, mensagem de erro que mostra caminho de arquivo, backup sem senha, arquivo `.env` no repositório.
- **Integridade** — o dado e o comportamento não mudam sem autorização. Quebra quando alguém escreve, apaga ou altera: criar usuário administrador, mudar preço, trocar o conteúdo de uma página.
- **Disponibilidade** — o serviço responde quando é preciso. Quebra quando alguém derruba, trava ou esgota recurso: apagar tabela, encher o disco, forçar o servidor a um laço infinito.

Duas extensões que aparecem com frequência:

- **Autenticidade** — quem está falando é quem diz ser. Quebra com session fixation, token previsível, certificado não verificado.
- **Rastreabilidade (não repúdio)** — ficou registrado quem fez o quê. Quebra quando não há log de acesso ou quando o log não é protegido.

Para classificar impacto, pergunte na ordem: **isto lê dado que não deveria? altera dado que não deveria? derruba o serviço?** Cada "sim" é um eixo da tríade comprometido.

## O vocabulário de referência (e o que cada um NÃO responde)

| Sigla | O que é | Responde | Não responde |
|-------|---------|----------|--------------|
| **CWE** | Common Weakness Enumeration: catálogo de **classes** de fraqueza no código | que tipo de erro é (ex.: CWE-89, injeção de SQL) | se o seu sistema tem esse erro, nem quão grave ele é aqui |
| **CVE** | registro público de uma falha **específica** em um produto e versão | qual falha conhecida afeta qual versão | falhas no seu código próprio (não têm CVE) |
| **CVSS** | pontuação técnica de severidade, de 0 a 10 | quão grave é a falha em abstrato | o risco do seu negócio, nem se você tem outros controles |
| **OWASP Top 10** | lista de consenso das categorias de risco mais comuns em aplicação web | onde olhar primeiro em aplicação web | profundidade técnica por item |
| **MITRE ATT&CK** | base de **comportamentos de adversário** (táticas e técnicas) | como um atacante costuma agir depois de entrar | qual falha existe no seu código |
| **CAPEC** | catálogo de padrões de ataque | como a fraqueza é atacada na prática | o que corrigir |

Faixas qualitativas do CVSS 3.1, para não inventar número: 0,1–3,9 baixa; 4,0–6,9 média; 7,0–8,9 alta; 9,0–10,0 crítica.

Duas regras que o agente nunca quebra ao usar este vocabulário:

1. **Não invente identificador.** Se não tem certeza de que existe CVE ou de que o CWE é aquele, diga que é a classe provável e explique o comportamento. Identificador inventado destrói a confiança de todo o relatório.
2. **CVSS não é risco.** O CVSS descreve a falha isolada; o risco depende de exposição, dado tocado e controles compensatórios. Use os dois, e mostre qual foi a evidência de cada nota.

## Boas práticas que resolvem a maior parte dos casos

- **Separe código de dado.** Consulta SQL vai com marcador de parâmetro (`?` ou `%s`), nunca com concatenação ou `f-string`. Vale para SQL, comando de sistema, LDAP, template e regex.
- **Valide na fronteira, e valide de novo na camada que executa.** Tamanho, tipo e formato; lista de permitidos é mais segura que lista de proibidos.
- **Nunca guarde senha em claro.** Hash com salt e custo (bcrypt, argon2id, scrypt, PBKDF2 com muitas iterações). Compare com comparação de tempo constante.
- **Mensagem de erro genérica para fora, detalhe para o log.** "Usuário ou senha inválidos" para o exterior; nunca revelar se o usuário existe.
- **Menor privilégio sempre.** Usuário de banco que só lê o que precisa, conexão somente leitura no caminho de leitura, serviço rodando sem root, chave de API com escopo mínimo.
- **Limite tentativas e registre o evento.** Rate limiting e bloqueio progressivo transformam uma falha de autenticação em algo caro de explorar.
- **Defesa em profundidade.** Duas barreiras independentes: consulta parametrizada **e** permissão restrita no banco. Se uma cair, a outra segura.
- **Segredo não fica no repositório.** `.env` fora do Git, chave rotacionável, e se um segredo entrou no histórico, ele precisa ser trocado — remover do arquivo não basta.
- **Atualize dependência.** Falha conhecida com versão corrigida disponível é dívida, não destino.
- **Não confie no cliente.** Validação no navegador é conveniência de interface; a decisão acontece no servidor.

## Como o agente usa este arquivo

1. Traduz o que a pessoa descreveu para ativo + vulnerabilidade + ameaça, e só então fala de risco.
2. Classifica impacto pelos eixos da tríade antes de dar nota.
3. Usa o vocabulário da tabela para nomear o problema com precisão, e declara quando um identificador é incerto.
4. Escolhe a recomendação pelo par defesa em profundidade + menor privilégio, não pela correção mais sofisticada.
5. Fecha com um jeito de **verificar** que a correção funcionou. Sem validação, a correção é fé.
