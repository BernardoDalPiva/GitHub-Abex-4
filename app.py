# =================================================================
# 1. IMPORTS
# =================================================================
import psycopg2
from psycopg2 import Error
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta, UTC # <-- UTC importado para a correção
from functools import wraps

# =================================================================
# 2. INICIALIZAÇÃO E CONFIGURAÇÃO DO APP FLASK
# =================================================================
app = Flask(__name__)
CORS(app)
# IMPORTANTE: Mude esta chave para uma sequência de caracteres complexa e secreta!
app.config['SECRET_KEY'] = 'uma-chave-secreta-muito-dificil-de-adivinhar-9a8b7c6d5e'

# =================================================================
# 3. DECORATOR PARA PROTEGER ROTAS DE ADMIN
# =================================================================
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({'erro': 'Formato do cabeçalho de autorização inválido.'}), 401

        if not token:
            return jsonify({'erro': 'Token de autenticação não fornecido!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            if not data.get('is_admin'):
                return jsonify({'erro': 'Acesso negado. Requer permissão de administrador.'}), 403
        except jwt.ExpiredSignatureError:
            return jsonify({'erro': 'Seu token expirou! Faça login novamente.'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'erro': 'Token inválido!'}), 401
        
        return f(*args, **kwargs)
    return decorated

# =================================================================
# 4. FUNÇÃO AUXILIAR DE CONEXÃO
# =================================================================
def conectar_banco():
    try:
        conexao = psycopg2.connect(
            host="localhost",
            database="biblioteca",
            user="postgres",
            password="decarli123" # Lembre-se de usar sua senha
        )
        return conexao
    except (Exception, Error) as error:
        print(f"Erro ao conectar ao PostgreSQL: {error}")
        return None

# =================================================================
# 5. ROTAS DA API (ENDPOINTS)
# =================================================================

# --- Rotas de Autenticação ---

@app.route('/cadastro', methods=['POST'])
def cadastrar_usuario():
    dados = request.get_json()
    # (Lógica de cadastro continua a mesma)
    nome = dados.get('nome')
    email = dados.get('email')
    senha = dados.get('senha')
    confirmar_senha = dados.get('confirmar_senha')
    cpf = dados.get('cpf')

    if not all([nome, email, senha, confirmar_senha, cpf]):
        return jsonify({"erro": "Todos os campos são obrigatórios."}), 400
    if senha != confirmar_senha:
        return jsonify({"erro": "As senhas não coincidem."}), 400
    if len(senha) < 8:
        return jsonify({"erro": "A senha deve ter no mínimo 8 caracteres."}), 400

    senha_hash = generate_password_hash(senha)
    conn = conectar_banco()
    if not conn: return jsonify({"erro": "Erro interno no servidor."}), 500
    try:
        cursor = conn.cursor()
        sql = "INSERT INTO usuarios (nome, email, cpf, senha_hash) VALUES (%s, %s, %s, %s);"
        cursor.execute(sql, (nome, email, cpf, senha_hash))
        conn.commit()
    except psycopg2.errors.UniqueViolation as e:
        if 'usuarios_email_key' in str(e): return jsonify({"erro": "Este e-mail já está em uso."}), 409
        if 'usuarios_cpf_key' in str(e): return jsonify({"erro": "Este CPF já está cadastrado."}), 409
        return jsonify({"erro": "Erro de duplicidade não identificado."}), 409
    except (Exception, Error) as error:
        return jsonify({"erro": f"Erro ao inserir dados: {error}"}), 500
    finally:
        if conn:
            cursor.close()
            conn.close()
    return jsonify({"mensagem": "Usuário cadastrado com sucesso!"}), 201

@app.route('/login', methods=['POST'])
def login_usuario():
    dados = request.get_json()
    email = dados.get('email')
    senha = dados.get('senha')
    if not email or not senha: return jsonify({"erro": "Email e senha são obrigatórios."}), 400

    conn = conectar_banco()
    if not conn: return jsonify({"erro": "Erro interno no servidor."}), 500
    try:
        cursor = conn.cursor()
        sql = "SELECT id, senha_hash, is_admin FROM usuarios WHERE email = %s;"
        cursor.execute(sql, (email,))
        usuario = cursor.fetchone()

        if not usuario or not check_password_hash(usuario[1], senha):
            return jsonify({"erro": "Email ou senha inválidos."}), 401
        
        token_payload = {
            'id': usuario[0],
            'is_admin': usuario[2],
            # CORRIGIDO: Usando datetime.now(UTC) para evitar o DeprecationWarning.
            'exp': datetime.now(UTC) + timedelta(hours=24)
        }
        token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({"mensagem": "Login realizado com sucesso!", "token": token})
    except (Exception, Error) as error:
        return jsonify({"erro": f"Erro ao consultar dados: {error}"}), 500
    finally:
        if conn:
            cursor.close()
            conn.close()

# --- Rotas de Livros ---

@app.route('/livros', methods=['GET']) # <-- ROTA CORRIGIDA, SEM ERROS DE DIGITAÇÃO
def get_livros():
    termo_busca = request.args.get('busca', '')
    conn = conectar_banco()
    if not conn: return jsonify({"erro": "Não foi possível conectar ao banco de dados"}), 500
    
    livros_lista = []
    try:
        cursor = conn.cursor()
        sql = "SELECT id, titulo, autor, ano_publicacao, genero, disponivel FROM livros"
        params = []
        if termo_busca:
            sql += " WHERE titulo ILIKE %s OR autor ILIKE %s OR genero ILIKE %s"
            like_query = f"%{termo_busca}%"
            params = [like_query, like_query, like_query]
        sql += " ORDER BY id;"
        
        cursor.execute(sql, params)
        registros = cursor.fetchall()
        
        for linha in registros:
            livros_lista.append({
                'id': linha[0], 'titulo': linha[1], 'autor': linha[2],
                'ano_publicacao': linha[3], 'genero': linha[4], 'disponivel': linha[5]
            })
    except (Exception, Error) as error:
        return jsonify({"erro": f"Erro ao consultar dados: {error}"}), 500
    finally:
        if conn:
            cursor.close()
            conn.close()
    return jsonify(livros_lista)

@app.route('/livros', methods=['POST'])
def adicionar_livro():
    dados = request.get_json()
    # (Lógica de adicionar livro continua a mesma)
    titulo = dados.get('titulo')
    autor = dados.get('autor')
    ano_publicacao = dados.get('ano_publicacao')
    genero = dados.get('genero')
    if not all([titulo, autor, ano_publicacao, genero]):
        return jsonify({"erro": "Dados incompletos"}), 400
    conn = conectar_banco()
    if not conn: return jsonify({"erro": "Não foi possível conectar ao banco de dados"}), 500
    try:
        cursor = conn.cursor()
        sql = "INSERT INTO livros (titulo, autor, ano_publicacao, genero) VALUES (%s, %s, %s, %s);"
        cursor.execute(sql, (titulo, autor, ano_publicacao, genero))
        conn.commit()
    except (Exception, Error) as error:
        return jsonify({"erro": f"Erro ao inserir dados: {error}"}), 500
    finally:
        if conn:
            cursor.close()
            conn.close()
    return jsonify({"mensagem": f"Livro '{titulo}' inserido com sucesso!"}), 201

@app.route('/livros/<int:id_livro>', methods=['DELETE'])
@admin_required # <-- Rota protegida, só admins podem acessar
def deletar_livro(id_livro):
    conn = conectar_banco()
    if not conn: return jsonify({"erro": "Não foi possível conectar ao banco de dados"}), 500
    try:
        cursor = conn.cursor()
        sql = "DELETE FROM livros WHERE id = %s;"
        cursor.execute(sql, (id_livro,))
        conn.commit()
        mensagem = f"Livro com ID {id_livro} deletado com sucesso!" if cursor.rowcount > 0 else f"Nenhum livro encontrado com o ID {id_livro}."
        return jsonify({"mensagem": mensagem})
    except (Exception, Error) as error:
        return jsonify({"erro": f"Erro ao deletar dados: {error}"}), 500
    finally:
        if conn:
            cursor.close()
            conn.close()

# =================================================================
# 6. EXECUÇÃO DO SERVIDOR
# =================================================================
if __name__ == '__main__':
    app.run(debug=True)