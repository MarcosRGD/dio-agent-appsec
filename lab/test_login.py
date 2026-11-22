#!/usr/bin/env python3
"""Teste de regressao: prova que o login vulneravel e exploravel e que o corrigido nao.

Roda 100% local, com banco descartavel criado na pasta lab/labdata/.
Uso:  python3 lab/test_login.py     (de qualquer diretorio)

Secao 1 documenta o comportamento do codigo VULNERAVEL (acha que ele falha).
Secao 2 e o que precisa passar: o codigo CORRIGIDO resiste aos mesmos ataques.
"""

import importlib.util
import os
import sqlite3
import sys
import time
from pathlib import Path

LAB = Path(__file__).resolve().parent
DADOS = LAB / "labdata"
VULN_DB = DADOS / "banco_de_dados.db"      # app.py usa nome relativo ao CWD
SEC_DB = DADOS / "corrigido.db"

USUARIO = "marcos"
SENHA = "S3nh@Forte"
ADMIN = "admin"
SENHA_ADMIN = "Adm1n#Forte"

# O que o atacante digita no campo de usuario.
BY1 = "admin' --"
BY2 = "' OR 1=1 --"
BY3 = "' UNION SELECT id, username, password, role FROM usuarios --"

falhas = []
total = 0


def check(nome, ok, detalhe=""):
    global total
    total += 1
    print(f"  [{'OK  ' if ok else 'FALHA'}] {nome}" + (f"  -> {detalhe}" if detalhe else ""))
    if not ok:
        falhas.append(nome)


def montar_bancos():
    DADOS.mkdir(exist_ok=True)
    for db in (VULN_DB, SEC_DB):
        db.unlink(missing_ok=True)
        db.with_suffix(".db-journal").unlink(missing_ok=True)

    # Banco do codigo vulneravel: senha em texto claro, esquema original.
    con = sqlite3.connect(VULN_DB)
    con.execute("CREATE TABLE usuarios (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)")
    con.executemany(
        "INSERT INTO usuarios (username, password, role) VALUES (?,?,?)",
        [(USUARIO, SENHA, "user"), (ADMIN, SENHA_ADMIN, "admin")],
    )
    con.commit()
    con.close()

    # Banco do codigo corrigido: so hash, esquema novo.
    con = sqlite3.connect(SEC_DB)
    con.execute("CREATE TABLE usuarios (id INTEGER PRIMARY KEY, username TEXT UNIQUE, senha_hash TEXT)")
    con.commit()
    con.close()


def carregar(nome, caminho):
    spec = importlib.util.spec_from_file_location(nome, caminho)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[nome] = mod
    spec.loader.exec_module(mod)
    return mod


def main():
    montar_bancos()

    # app.py abre 'banco_de_dados.db' relativo ao diretorio atual.
    os.chdir(DADOS)
    vuln = carregar("app_vulneravel", LAB / "app.py")

    os.environ["APP_DB"] = str(SEC_DB)
    seg = carregar("app_corrigido", LAB / "app_corrigido.py")

    print("\n1) CODIGO VULNERAVEL (esperado: ser invadido)")
    check("login correto funciona", vuln.fazer_login(USUARIO, SENHA) == "Acesso Permitido!")
    check("senha errada e negada", vuln.fazer_login(USUARIO, "errada") == "Acesso Negado.")
    r = vuln.fazer_login(BY1, "x")
    check("bypass com comentario entra como admin", r == "Acesso Permitido!", f"{BY1!r} -> {r!r}")
    r = vuln.fazer_login(BY2, "x")
    check("tautologia entra sem senha", r == "Acesso Permitido!", f"{BY2!r} -> {r!r}")
    r = vuln.fazer_login(BY3, "x")
    check("UNION entra sem senha", r == "Acesso Permitido!", f"{BY3!r} -> {r!r}")
    # a consulta montada pelo app, replicada aqui, devolve a tabela inteira
    fora = sqlite3.connect(VULN_DB)
    dump = fora.execute(
        f"SELECT * FROM usuarios WHERE username = '{BY3}' AND password = 'x'"
    ).fetchall()
    fora.close()
    check("vaza todos os usuarios e senhas em claro", len(dump) >= 2,
          f"{len(dump)} linhas, roles={[d[3] for d in dump]}")

    print("\n2) CODIGO CORRIGIDO (esperado: resistir a tudo)")
    seg.criar_usuario(USUARIO, SENHA)
    seg.criar_usuario(ADMIN, SENHA_ADMIN)

    check("login correto funciona", seg.fazer_login(USUARIO, SENHA) == "Acesso Permitido!")
    check("senha errada e negada", seg.fazer_login(USUARIO, "errada") == "Acesso Negado.")
    for payload in (BY1, BY2, BY3):
        r = seg.fazer_login(payload, "x")
        check(f"rejeita payload {payload!r}", r == "Acesso Negado.", f"{r!r}")
    check("rejeita senha vazia", seg.fazer_login(USUARIO, "") == "Acesso Negado.")
    check("rejeita None", seg.fazer_login(None, SENHA) == "Acesso Negado.")
    check("rejeita entrada gigante", seg.fazer_login("a" * 5000, SENHA) == "Acesso Negado.")

    con = sqlite3.connect(SEC_DB)
    linha = con.execute("SELECT senha_hash FROM usuarios WHERE username = ?", (USUARIO,)).fetchone()
    check("senha nao esta em claro no banco", SENHA not in linha[0], linha[0][:22] + "...")
    check("hash tem salt e iteracoes",
          linha[0].startswith("pbkdf2_sha256$") and len(linha[0].split("$")) == 4)

    # reproduz o que app_corrigido.py faz: abre o banco em modo somente leitura
    ro = sqlite3.connect(f"file:{SEC_DB}?mode=ro", uri=True)
    try:
        ro.execute("INSERT INTO usuarios (username, senha_hash) VALUES ('x','y')")
        ro.commit()
        check("conexao de leitura nao escreve", False, "escrita passou")
    except sqlite3.OperationalError as e:
        check("conexao de leitura nao escreve", True, str(e))
    ro.close()

    n = sqlite3.connect(SEC_DB).execute("SELECT COUNT(*) FROM usuarios").fetchone()[0]
    check("tabela intacta depois dos ataques", n == 2, f"{n} linhas")

    t0 = time.perf_counter()
    seg.fazer_login(USUARIO, "errada")
    existente = time.perf_counter() - t0
    t0 = time.perf_counter()
    seg.fazer_login("nao_existe_essa_conta", "errada")
    inexistente = time.perf_counter() - t0
    delta = abs(existente - inexistente) / max(existente, inexistente) * 100
    check("tempo parecido p/ usuario inexistente (anti-enumeracao)", delta < 25,
          f"existente={existente*1000:.0f}ms inexistente={inexistente*1000:.0f}ms delta={delta:.1f}%")

    print(f"\n{total - len(falhas)}/{total} verificacoes passaram")
    if falhas:
        print("FALHAS: " + "; ".join(falhas))
        return 1
    print("RESULTADO: TUDO OK — injecao de SQL mitigada, senha com hash, sem enumeracao por tempo")
    return 0


if __name__ == "__main__":
    sys.exit(main())
