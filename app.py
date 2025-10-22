# =================================================================
# 1. IMPORTS
# =================================================================
import psycopg2
from psycopg2 import Error
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta, UTC
from functools import wraps

# --- ADICIONADO PARA O CHAT ---
from flask_socketio import SocketIO, emit, join_room, leave_room
# -----------------------------

# =================================================================
# 2. INICIALIZAÇÃO E CONFIGURAÇÃO DO APP FLASK
# =================================================================
app = Flask(__name__)
CORS(app)
# IMPORTANTE: Mude esta chave para uma sequência de caracteres complexa e secreta!
app.config['SECRET_KEY'] = 'uma-chave-secreta-muito-dificil-de-adivinhar-9a8b7c6d5e'

# --- ADICIONADO PARA O CHAT ---
# Inicializa o SocketIO envolvendo o 'app' Flask
# O cors_allowed_origins="*" é vital para o chat.html poder se conectar
socketio = SocketIO(app, cors_allowed_origins="*")
# -----------------------------

# =================================================================
# 3. DECORATORS DE AUTENTICAÇÃO
# =================================================================

# Este decorator (que você já tinha) protege rotas de ADMIN
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
            # Passa os dados do usuário decodificado para a rota
            kwargs['usuario_logado'] = data 
        except jwt.ExpiredSignatureError:
            return jsonify({'erro': 'Seu token expirou! Faça login novamente.'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'erro': 'Token inválido!'}), 401
        
        return f(*args, **kwargs)
    return decorated

# --- ADICIONADO PARA O CHAT ---
# Criei um novo decorator que exige APENAS login (não precisa ser admin)
# Usaremos isso para o histórico do chat
def login_required(f):
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
            # A única diferença: não há verificação de 'is_admin'
            kwargs['usuario_logado'] = data # Passa os dados do usuário (id, nome, etc.)
        except jwt.ExpiredSignatureError:
            return jsonify({'erro': 'Seu token expirou! Faça login novamente.'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'erro': 'Token inválido!'}), 401
        
        return f(*args, **kwargs)
    return decorated
# -----------------------------

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
# 5. ROTAS DA API (ENDPOINTS HTTP)
# =================================================================

# --- Rotas de Autenticação (Sem alteração) ---

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
        # Seleciona também o NOME do usuário
        sql = "SELECT id, nome, senha_hash, is_admin FROM usuarios WHERE email = %s;"
        cursor.execute(sql, (email,))
        usuario = cursor.fetchone() # (id, nome, senha_hash, is_admin)

        if not usuario or not check_password_hash(usuario[2], senha):
            return jsonify({"erro": "Email ou senha inválidos."}), 401
        
        token_payload = {
            'id': usuario[0],
            'nome': usuario[1], # Adiciona o nome ao token
            'is_admin': usuario[3],
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

# --- Rotas de Livros (Sem alteração) ---

@app.route('/livros', methods=['GET'])
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
@admin_required # <-- Rota protegida (kwargs['usuario_logado'] é injetado)
def deletar_livro(id_livro, **kwargs): # Adicionado **kwargs
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

# --- ADICIONADO PARA O CHAT ---
@app.route('/historico/<string:sala_id>', methods=['GET'])
@login_required # Protegido por login
def get_historico_chat(sala_id, **kwargs):
    """Busca o histórico de mensagens de uma sala específica."""
    conn = conectar_banco()
    if not conn: return jsonify({"erro": "Erro de conexão com o banco"}), 500
    
    mensagens_lista = []
    try:
        cursor = conn.cursor()
        # Busca mensagens E o nome do remetente
        sql = """
            SELECT m.texto, m.timestamp, u.nome
            FROM mensagens m
            JOIN usuarios u ON m.remetente_id = u.id
            WHERE m.sala_id = %s
            ORDER BY m.timestamp ASC;
        """
        cursor.execute(sql, (sala_id,))
        registros = cursor.fetchall()
        
        for linha in registros:
            mensagens_lista.append({
                'texto': linha[0],
                'time': linha[1].strftime('%H:%M'), # Formata a hora
                'remetente': linha[2]
            })
    except (Exception, Error) as error:
        return jsonify({"erro": f"Erro ao consultar histórico: {error}"}), 500
    finally:
        if conn:
            cursor.close()
            conn.close()
    return jsonify(mensagens_lista)
# -----------------------------

# =================================================================
# 6. ROTAS DO CHAT (SOCKET.IO) - (NOVO)
# =================================================================

@socketio.on('connect')
def handle_connect():
    """Ocorre quando um usuário abre a página chat.html."""
    print(f'Cliente conectado ao WebSocket: {request.sid}')

@socketio.on('disconnect')
def handle_disconnect():
    """Ocorre quando um usuário fecha a página."""
    print(f'Cliente desconectado: {request.sid}')

@socketio.on('entrar_sala')
def handle_join_room(data):
    """Ocorre quando o usuário clica em uma conversa no frontend."""
    sala_id = data.get('sala')
    if not sala_id:
        return
        
    join_room(sala_id)
    print(f'Cliente {request.sid} entrou na sala: {sala_id}')

@socketio.on('enviar_mensagem')
def handle_send_message(data):
    """Ocorre quando um usuário envia uma mensagem no formulário."""
    sala_id = data.get('sala')
    if not sala_id:
        return

    print(f"Mensagem recebida na sala '{sala_id}': {data.get('texto')}")

    # !! INTEGRAÇÃO COM SEU BANCO DE DADOS !!
    # Salva a mensagem no seu banco de dados 'biblioteca'
    conn = conectar_banco()
    if conn:
        try:
            cursor = conn.cursor()
            sql = """
                INSERT INTO mensagens (sala_id, remetente_id, texto) 
                VALUES (%s, %s, %s)
            """
            # O frontend (chat.html) já está enviando 'remetente_id'
            cursor.execute(sql, (data.get('sala'), data.get('remetente_id'), data.get('texto')))
            conn.commit()
            print("Mensagem salva no banco de dados.")
        except (Exception, Error) as e:
            print(f"Erro ao salvar mensagem no DB: {e}")
            conn.rollback() # Desfaz a tentativa
        finally:
            if cursor: cursor.close()
            if conn: conn.close()
    
    # Re-transmite (emite) a mensagem para TODOS na mesma sala
    emit('nova_mensagem', data, to=sala_id)

# =================================================================
# 7. EXECUÇÃO DO SERVIDOR (MODIFICADO)
# =================================================================
if __name__ == '__main__':
    # !! MODIFICADO !!
    # Use 'socketio.run()' em vez de 'app.run()'
    # Isso inicia o servidor HTTP e o servidor WebSocket juntos.
    print("Iniciando servidor Flask com Socket.IO...")
    socketio.run(app, debug=True, port=5000)
