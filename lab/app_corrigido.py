"""Login corrigido: consulta parametrizada + senhas com hash (PBKDF2-SHA256).

Correcoes sobre a versao original:
  * SQL injection: placeholders '?' + tupla de parametros (nenhuma interpolacao).
  * Conexao aberta em modo somente-leitura (mode=ro): defesa em profundidade,
    o caminho de login nao consegue escrever nem executar DDL.
  * Senha nunca mais comparada em texto claro no SQL: hash PBKDF2 + salt por usuario,
    verificacao com hmac.compare_digest (tempo constante).
  * Hash fantasma quando o usuario nao existe: custo de tempo equivalente,
    evita enumeracao de usuarios por timing.
  * Conexao sempre fechada (context managers), erros de infra nao vazam detalhe.
  * Validacao de entrada e mensagem generica unica.

Fora de escopo desta funcao (deve ficar na camada de cima):
  * Rate limiting / lockout por conta e por IP (ex.: slowapi, Redis, fail2ban).
  * Sessao: emitir token/cookie HttpOnly+Secure+SameSite em vez de so retornar texto.
  * Migracao dos usuarios existentes: rehash na proxima autenticacao bem-sucedida
    (se o registro ainda estiver em claro, compare uma unica vez e regrave como hash).
"""

import hashlib
import hmac
import os
import secrets
import sqlite3
from contextlib import closing

DB_PATH = os.environ.get("APP_DB", "banco_de_dados.db")

ALGORITMO = "pbkdf2_sha256"
ITERACOES = 600_000          # OWASP 2023 p/ PBKDF2-HMAC-SHA256
SALT_BYTES = 16
MAX_USUARIO = 64
MAX_SENHA = 1024             # senha longa e legitima; so corta abuso
MSG_NEGADO = "Acesso Negado."
MSG_PERMITIDO = "Acesso Permitido!"


def gerar_hash(senha: str) -> str:
    """Formato: pbkdf2_sha256$<iteracoes>$<salt_hex>$<hash_hex>"""
    salt = secrets.token_bytes(SALT_BYTES)
    dk = hashlib.pbkdf2_hmac("sha256", senha.encode("utf-8"), salt, ITERACOES)
    return f"{ALGORITMO}${ITERACOES}${salt.hex()}${dk.hex()}"


def verificar_hash(senha: str, armazenado: str) -> bool:
    try:
        algoritmo, iteracoes, salt_hex, esperado = armazenado.split("$")
        if algoritmo != ALGORITMO:
            return False
        dk = hashlib.pbkdf2_hmac(
            "sha256", senha.encode("utf-8"), bytes.fromhex(salt_hex), int(iteracoes)
        )
    except (AttributeError, ValueError):
        return False  # registro corrompido/legado: nega sem estourar excecao
    return hmac.compare_digest(dk.hex(), esperado)


# Gastar o mesmo tempo quando o usuario nao existe.
_HASH_FANTASMA = gerar_hash(secrets.token_hex(16))

_SQL_LOGIN = "SELECT senha_hash FROM usuarios WHERE username = ?"


def _ler_hash(usuario: str) -> str | None:
    uri = f"file:{DB_PATH}?mode=ro"
    with closing(sqlite3.connect(uri, uri=True, timeout=5)) as conexao:
        with conexao:
            linha = conexao.execute(_SQL_LOGIN, (usuario,)).fetchone()
    return linha[0] if linha else None


def fazer_login(usuario: str, senha: str) -> str:
    if not isinstance(usuario, str) or not isinstance(senha, str):
        return MSG_NEGADO
    if not 1 <= len(usuario) <= MAX_USUARIO or not 1 <= len(senha) <= MAX_SENHA:
        return MSG_NEGADO

    try:
        armazenado = _ler_hash(usuario)
    except sqlite3.Error:
        # Log interno (sem senha) fica no chamador; para fora, mensagem generica.
        return MSG_NEGADO

    if armazenado is None:
        verificar_hash(senha, _HASH_FANTASMA)  # tempo constante
        return MSG_NEGADO

    return MSG_PERMITIDO if verificar_hash(senha, armazenado) else MSG_NEGADO


def criar_usuario(usuario: str, senha: str) -> None:
    """Grava o usuario com hash. Nunca armazene a senha em claro."""
    if not 1 <= len(usuario) <= MAX_USUARIO or not 1 <= len(senha) <= MAX_SENHA:
        raise ValueError("usuario ou senha fora dos limites")
    with closing(sqlite3.connect(DB_PATH, timeout=5)) as conexao:
        with conexao:
            conexao.execute(
                "INSERT INTO usuarios (username, senha_hash) VALUES (?, ?)",
                (usuario, gerar_hash(senha)),
            )
