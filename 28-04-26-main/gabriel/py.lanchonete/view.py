import os
import jwt
import random
import datetime
from flask import Flask, jsonify, request, make_response
from main import app, get_db_connection
from funcao import (
    verificar_senha,
    criptografar,
    checar_senha,
    gerar_token,
    enviando_email
)

SECRET_KEY = "segredo_super"
UPLOAD_FOLDER = os.path.join(app.config.get('UPLOAD_FOLDER', 'static/uploads'), "usuarios")

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# ==========================================
# FUNÇÃO AUXILIAR: REUSO DE SENHA
# ==========================================
def verificar_reuso_senha(id_usuario, senha_nova, cur):
    cur.execute("SELECT SENHA_HASH FROM HISTORICO_SENHAS WHERE ID_USUARIO = ?", (id_usuario,))
    historico = cur.fetchall()
    for (hash_antigo,) in historico[-3:]:
        if checar_senha(senha_nova, hash_antigo):
            return True
    return False

# ==========================================
# ROTA: LISTAR TODOS OS USUÁRIOS
# ==========================================
@app.route('/usuarios', methods=['GET'])
def listar_usuarios():
    con = get_db_connection()
    cur = con.cursor()
    try:
        cur.execute("SELECT ID_USUARIO, NOME, EMAIL, TIPO_NOME, BLOQUEADO FROM USUARIO")
        usuarios = cur.fetchall()
        resultado = []
        for u in usuarios:
            resultado.append({
                'id': u[0], 'nome': u[1], 'email': u[2], 'tipo': u[3], 'bloqueado': "Sim" if u[4] else "Não"
            })
        return jsonify(resultado), 200
    except Exception as e:
        return jsonify({'erro': f"Erro ao listar: {str(e)}"}), 500
    finally:
        cur.close()
        con.close()

# ==========================================
# ROTA: BUSCAR POR NOME
# ==========================================
@app.route('/admin/buscar_nome', methods=['GET'])
def buscar_usuario_nome():
    nome_busca = request.args.get('nome', '')

    con = get_db_connection()
    cur = con.cursor()
    try:
        # Buscando na sua tabela USUARIO
        cur.execute("""
            SELECT ID_USUARIO, NOME, EMAIL FROM USUARIO 
            WHERE UPPER(NOME) LIKE UPPER(?)
        """, (f'%{nome_busca}%',))

        usuarios = cur.fetchall()
        resultado = [{'id': u[0], 'nome': u[1], 'email': u[2]} for u in usuarios]
        return jsonify(resultado), 200
    except Exception as e:
        return jsonify({'erro': str(e)}), 500
    finally:
        cur.close()
        con.close()

# ==========================================
# ROTA: CRIAR USUÁRIO
# ==========================================
@app.route('/criar_usuario', methods=['POST'])
def criar_usuario_novo():
    con = get_db_connection()
    cur = con.cursor()
    try:
        nome = request.form.get('nome')
        email = request.form.get('email')
        senha = request.form.get('senha')
        id_tipo_input = request.form.get('id_tipo', 2)
        id_tipo = int(id_tipo_input)

        if id_tipo == 1:
            tipo_nome = 'admin'
        else:
            id_tipo = 2
            tipo_nome = 'garcom'

        if not all([nome, email, senha]):
            return jsonify({'erro': 'Campos obrigatórios ausentes'}), 400

        cur.execute("SELECT id_usuario FROM USUARIO WHERE email=?", (email,))
        if cur.fetchone():
            return jsonify({'erro': 'Email já cadastrado'}), 409

        erro_v = verificar_senha(senha)
        if erro_v: return jsonify({'erro': erro_v}), 400

        senha_hash = criptografar(senha)
        cur.execute("""
            INSERT INTO USUARIO (nome, email, senha, id_tipo, tipo_nome, conta_confirmada, bloqueado, tentativas_login)
            VALUES (?, ?, ?, ?, ?, FALSE, FALSE, 0)
            RETURNING id_usuario
        """, (nome, email, senha_hash, id_tipo, tipo_nome))

        id_user = cur.fetchone()[0]
        cur.execute("INSERT INTO HISTORICO_SENHAS (id_usuario, senha_hash) VALUES (?, ?)", (id_user, senha_hash))
        codigo = str(random.randint(100000, 999999))
        cur.execute("INSERT INTO CODIGOS (id_usuario, codigo, tipo) VALUES (?, ?, 'confirmacao')", (id_user, codigo))

        con.commit()
        enviando_email(email, "Confirmação", f"Código: {codigo}")
        return jsonify({'mensagem': f'Conta de {tipo_nome} criada!', 'id_usuario': id_user}), 201
    except Exception as e:
        con.rollback()
        return jsonify({'erro': str(e)}), 500
    finally:
        cur.close()
        con.close()

# ==========================================
# ROTA: EDITAR USUÁRIO
# ==========================================
@app.route('/editar_usuario/<int:id_usuario>', methods=['PUT', 'POST'])
def editar_usuario(id_usuario):
    con = get_db_connection()
    cur = con.cursor()
    try:
        cur.execute("SELECT SENHA, NOME, EMAIL FROM USUARIO WHERE ID_USUARIO = ?", (id_usuario,))
        res = cur.fetchone()
        if not res: return jsonify({'erro': 'Usuário não encontrado'}), 404

        hash_atual, nome_at, email_at = res
        nome = request.form.get('nome') or nome_at
        email = request.form.get('email') or email_at
        senha_nova = request.form.get('senha')

        senha_final = hash_atual
        if senha_nova and senha_nova.strip() != "":
            if verificar_reuso_senha(id_usuario, senha_nova, cur):
                return jsonify({'erro': 'Senha já usada recentemente.'}), 400
            cur.execute("INSERT INTO HISTORICO_SENHAS (ID_USUARIO, SENHA_HASH) VALUES (?, ?)", (id_usuario, hash_atual))
            senha_final = criptografar(senha_nova)

        cur.execute("UPDATE USUARIO SET NOME = ?, EMAIL = ?, SENHA = ? WHERE ID_USUARIO = ?",
                    (nome, email, senha_final, id_usuario))
        con.commit()
        return jsonify({'mensagem': 'Atualizado com sucesso!'}), 200
    except Exception as e:
        con.rollback()
        return jsonify({'erro': str(e)}), 500
    finally:
        cur.close()
        con.close()

# ==========================================
# ROTA: EXCLUIR USUÁRIO
# ==========================================
@app.route('/excluir_usuario/<int:id_usuario>', methods=['DELETE'])
def excluir_usuario(id_usuario):
    con = get_db_connection()
    cur = con.cursor()
    try:
        cur.execute("DELETE FROM CODIGOS WHERE ID_USUARIO = ?", (id_usuario,))
        cur.execute("DELETE FROM HISTORICO_SENHAS WHERE ID_USUARIO = ?", (id_usuario,))
        cur.execute("DELETE FROM USUARIO WHERE ID_USUARIO = ?", (id_usuario,))
        if cur.rowcount == 0: return jsonify({'erro': 'Usuário não encontrado.'}), 404
        con.commit()
        return jsonify({'mensagem': 'Removido com sucesso.'}), 200
    except Exception as e:
        con.rollback()
        return jsonify({'erro': f"Erro ao excluir: {str(e)}"}), 500
    finally:
        cur.close()
        con.close()

# ==========================================
# ROTA: LOGIN
# ==========================================
@app.route('/login', methods=['POST'])
def login():
    con = get_db_connection()
    cur = con.cursor()
    try:
        dados = request.get_json(silent=True) or request.form
        email = dados.get('email')
        senha = dados.get('senha')
        cur.execute("SELECT id_usuario, senha, nome, conta_confirmada, id_tipo, tipo_nome FROM USUARIO WHERE email=?", (email,))
        user = cur.fetchone()
        if not user: return jsonify({'erro': 'Não encontrado'}), 404
        id_u, s_db, nome, conf, id_t, t_nome = user
        if not conf: return jsonify({'erro': 'Confirme o email'}), 403
        if checar_senha(senha, s_db):
            token = gerar_token(id_u)
            return jsonify({'token': token, 'id': id_u, 'nome': nome, 'tipo': t_nome, 'id_tipo': id_t}), 200
        return jsonify({'erro': 'Senha incorreta'}), 401
    finally:
        cur.close()
        con.close()

# ==========================================
# ROTA: CONFIRMAR CÓDIGO
# ==========================================
@app.route('/confirmar_codigo', methods=['POST'])
def confirmar_codigo():
    con = get_db_connection()
    cur = con.cursor()
    try:
        dados = request.get_json(silent=True) or request.form
        id_user = dados.get('id_usuario')
        codigo = dados.get('codigo')
        cur.execute("SELECT id FROM CODIGOS WHERE id_usuario=? AND codigo=? AND utilizado=FALSE", (id_user, codigo))
        if not cur.fetchone(): return jsonify({'erro': 'Código inválido'}), 400
        cur.execute("UPDATE USUARIO SET conta_confirmada=TRUE WHERE id_usuario=?", (id_user,))
        cur.execute("UPDATE CODIGOS SET utilizado=TRUE WHERE id_usuario=?", (id_user,))
        con.commit()
        return jsonify({'mensagem': 'Conta confirmada!'}), 200
    finally:
        cur.close()
        con.close()

@app.route('/logout', methods=['POST'])
def logout():
    resp = make_response(jsonify({'mensagem': 'Logout realizado'}), 200)
    resp.delete_cookie('access_token')
    return resp