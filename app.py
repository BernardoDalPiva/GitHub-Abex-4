import os
import psycopg2
from psycopg2 import Error, errors # Adicionado 'errors' para 'UniqueViolation'
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask_socketio import SocketIO, emit, join_room, leave_room

DB_HOST = os.getenv('DB_HOST', 'localhost')
DB_NAME = os.getenv('DB_NAME', 'biblioteca')  
DB_USER = os.getenv('DB_USER', 'postgres')
DB_PASS = os.getenv('DB_PASS', 'decarli123')  

SECRET_KEY = os.getenv('SECRET_KEY', 'uma-chave-secreta-muito-dificil-de-adivinhar-9a8b7c6d5e')
JWT_ALGO = 'HS256'

# -----------------------
# FLASK + SOCKET.IO
# -----------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)  # CORS corrigido
socketio = SocketIO(app, cors_allowed_origins="*")

# -----------------------
# Helpers: conexão DB
# -----------------------
def conectar_banco():
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASS
        )
        return conn
    except Exception as e:
        print(f"[DB] Erro ao conectar: {e}")
        return None


# -----------------------
# Decorators de autenticação
# -----------------------
def _extrair_token_do_header():
    """Retorna token puro ou None"""
    auth = request.headers.get('Authorization', None)
    if not auth:
        return None
    parts = auth.split()
    if len(parts) != 2:
        return None
    return parts[1]


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = _extrair_token_do_header()
        if not token:
            return jsonify({"erro": "Token de autenticação não fornecido."}), 401
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGO])
            kwargs['usuario_logado'] = payload
        except jwt.ExpiredSignatureError:
            return jsonify({"erro": "Token expirado."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"erro": "Token inválido."}), 401
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = _extrair_token_do_header()
        if not token:
            return jsonify({"erro": "Token de autenticação não fornecido."}), 401
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGO])
            if not payload.get('is_admin'):
                return jsonify({"erro": "Acesso negado (somente admin)."}), 403
            kwargs['usuario_logado'] = payload
        except jwt.ExpiredSignatureError:
            return jsonify({"erro": "Token expirado."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"erro": "Token inválido."}), 401
        return f(*args, **kwargs)
    return decorated


# -----------------------
# Util: registrar interação + emitir via socket
# -----------------------
def registrar_interacao(usuario_destino_id, tipo, mensagem, link=None):
    conn = conectar_banco()
    if not conn:
        print("[Interação] Erro ao conectar ao DB para registrar interação.")
        return
    cursor = None
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO interacoes (usuario_id, tipo, mensagem, link) VALUES (%s, %s, %s, %s) RETURNING id, timestamp;",
            (usuario_destino_id, tipo, mensagem, link)
        )
        conn.commit()
        row = cursor.fetchone()
        # Emite notificação em tempo real
        socketio.emit('nova_interacao', {
            'usuario_id': usuario_destino_id,
            'tipo': tipo,
            'mensagem': mensagem,
            'link': link,
            'id': row[0] if row else None,
            'timestamp': row[1].isoformat() if row and row[1] else None
        })
    except Exception as e:
        print("[Interação] Erro ao registrar:", e)
        if conn:
            conn.rollback()
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


# -----------------------
# ROTAS: Cadastro / Login
# -----------------------
@app.route('/cadastro', methods=['POST'])
def cadastrar_usuario():
    dados = request.get_json() or {}
    nome = dados.get('nome')
    email = dados.get('email')
    senha = dados.get('senha')
    confirmar = dados.get('confirmar_senha')
    cpf = dados.get('cpf')

    if not all([nome, email, senha, confirmar, cpf]):
        return jsonify({"erro": "Todos os campos são obrigatórios."}), 400
    if senha != confirmar:
        return jsonify({"erro": "As senhas não coincidem."}), 400
    if len(senha) < 8:
        return jsonify({"erro": "Senha muito curta."}), 400

    senha_hash = generate_password_hash(senha)
    conn = conectar_banco()
    if not conn:
        return jsonify({"erro": "Erro interno (DB)."}), 500
    cursor = None
    try:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO usuarios (nome, email, cpf, senha_hash) VALUES (%s, %s, %s, %s);",
                       (nome, email, cpf, senha_hash))
        conn.commit()
        return jsonify({"mensagem": "Usuário cadastrado com sucesso!"}), 201
    except errors.UniqueViolation: 
        conn.rollback()
        return jsonify({"erro": "E-mail ou CPF já cadastrado."}), 409
    except Exception as e:
        conn.rollback()
        print("[Cadastro] Erro:", e)
        return jsonify({"erro": "Erro ao cadastrar usuário."}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


@app.route('/login', methods=['POST'])
def login_usuario():
    dados = request.get_json() or {}
    email = dados.get('email')
    senha = dados.get('senha')
    if not email or not senha:
        return jsonify({"erro": "Email e senha obrigatórios."}), 400
    conn = conectar_banco()
    if not conn:
        return jsonify({"erro": "Erro interno (DB)."}), 500
    cursor = None
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, nome, senha_hash, is_admin FROM usuarios WHERE email = %s;", (email,))
        row = cursor.fetchone()
        if not row:
            return jsonify({"erro": "Email ou senha inválidos."}), 401
        uid, nome, senha_hash, is_admin = row
        if not check_password_hash(senha_hash, senha):
            return jsonify({"erro": "Email ou senha inválidos."}), 401
        payload = {
            'id': uid,
            'nome': nome,
            'is_admin': bool(is_admin),
            'exp': datetime.now(timezone.utc) + timedelta(hours=24)
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGO)
        return jsonify({"mensagem": "Login OK", "token": token})
    except Exception as e:
        print("[Login] Erro:", e)
        return jsonify({"erro": "Erro ao efetuar login."}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

# -----------------------
# ROTAS: LIVROS
# -----------------------
@app.route('/livros', methods=['GET'])
def get_livros():
    termo = request.args.get('busca', '')
    conn = conectar_banco()
    if not conn:
        return jsonify({"erro": "Erro de conexão"}), 500
    cursor = None
    try:
        cursor = conn.cursor()
        sql = "SELECT id, titulo, autor, ano_publicacao, genero, disponivel, coalesce(dono_id, NULL) FROM livros"
        params = []
        if termo:
            sql += " WHERE titulo ILIKE %s OR autor ILIKE %s OR genero ILIKE %s"
            like = f"%{termo}%"
            params = [like, like, like]
        sql += " ORDER BY id;"
        cursor.execute(sql, params)
        rows = cursor.fetchall()
        livros = [{
            'id': r[0], 'titulo': r[1], 'autor': r[2], 'ano_publicacao': r[3],
            'genero': r[4], 'disponivel': r[5], 'dono_id': r[6]
        } for r in rows]
        return jsonify(livros)
    except Exception as e:
        print("[Livros] Erro ao buscar:", e)
        return jsonify({"erro": "Erro ao consultar livros."}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


@app.route('/livros', methods=['POST'])
@login_required
def adicionar_livro(usuario_logado):
    dados = request.get_json() or {}
    titulo = dados.get('titulo'); autor = dados.get('autor')
    ano = dados.get('ano_publicacao'); genero = dados.get('genero')
    if not all([titulo, autor, ano, genero]):
        return jsonify({"erro": "Dados incompletos."}), 400
    conn = conectar_banco()
    if not conn: return jsonify({"erro": "Erro de conexão"}), 500
    cursor = None
    try:
        cursor = conn.cursor()
        dono_id = usuario_logado.get('id')
        cursor.execute("INSERT INTO livros (titulo, autor, ano_publicacao, genero, disponivel, dono_id) VALUES (%s,%s,%s,%s,TRUE,%s);",
                       (titulo, autor, ano, genero, dono_id))
        conn.commit()
        return jsonify({"mensagem": f"Livro '{titulo}' inserido com sucesso!"}), 201
    except Exception as e:
        conn.rollback()
        print("[Livros] Erro ao inserir:", e)
        return jsonify({"erro": "Erro ao inserir livro."}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

@app.route('/livros/<int:id_livro>', methods=['DELETE'])
@login_required
def deletar_livro(id_livro, usuario_logado):
    conn = conectar_banco()
    if not conn: return jsonify({"erro": "Erro de conexão"}), 500
    cursor = None
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM livros WHERE id = %s;", (id_livro,))
        conn.commit()
        if cursor.rowcount == 0:
            return jsonify({"mensagem": f"Nenhum livro encontrado com ID {id_livro}."})
        return jsonify({"mensagem": f"Livro com ID {id_livro} deletado com sucesso!"})
    except Exception as e:
        conn.rollback()
        print("[Livros] Erro ao deletar:", e)
        return jsonify({"erro": "Erro ao deletar livro."}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

# -----------------------
# ROTAS: USUÁRIOS
# -----------------------
@app.route('/usuarios', methods=['GET'])
@login_required
def get_usuarios(usuario_logado):
    conn = conectar_banco()
    if not conn: return jsonify({"erro": "Erro de conexão"}), 500
    cursor = None
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, nome FROM usuarios WHERE id != %s ORDER BY nome;", (usuario_logado['id'],))
        rows = cursor.fetchall()
        usuarios = [{"id": r[0], "nome": r[1]} for r in rows]
        return jsonify(usuarios)
    except Exception as e:
        print("[Usuarios] Erro:", e)
        return jsonify({"erro": "Erro ao listar usuários."}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

# -----------------------
# ROTAS: HISTÓRICO DO CHAT
# -----------------------
@app.route('/historico/<string:sala_id>', methods=['GET'])
@login_required
def get_historico_chat(sala_id, usuario_logado):
    conn = conectar_banco()
    if not conn: return jsonify({"erro": "Erro de conexão"}), 500
    cursor = None
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT m.texto, m.timestamp, u.nome
            FROM mensagens m
            LEFT JOIN usuarios u ON m.remetente_id = u.id
            WHERE m.sala_id = %s
            ORDER BY m.timestamp ASC;
        """, (sala_id,))
        rows = cursor.fetchall()
        mensagens = []
        for r in rows:
            ts = r[1].strftime('%H:%M') if r[1] else ''
            mensagens.append({'texto': r[0], 'time': ts, 'remetente': r[2]})
        return jsonify(mensagens)
    except Exception as e:
        print("[Historico] Erro:", e)
        return jsonify({"erro": "Erro ao recuperar histórico."}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

# -----------------------
# ROTAS: EMPRESTIMO / DEVOLUÇÃO
# -----------------------
@app.route('/emprestimo', methods=['POST'])
@login_required
def registrar_emprestimo(usuario_logado):
    dados = request.get_json() or {}
    livro_id = dados.get('livro_id'); usuario_id = dados.get('usuario_id')
    if not all([livro_id, usuario_id]):
        return jsonify({"erro": "Parâmetros faltando."}), 400
    conn = conectar_banco()
    if not conn: return jsonify({"erro": "Erro de conexão"}), 500
    cursor = None
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT disponivel FROM livros WHERE id = %s;", (livro_id,))
        row = cursor.fetchone()
        if not row:
            return jsonify({"erro": "Livro não encontrado."}), 404
        if not row[0]:
            return jsonify({"erro": "Livro já emprestado."}), 400
        cursor.execute("INSERT INTO emprestimos (livro_id, usuario_id) VALUES (%s, %s);", (livro_id, usuario_id))
        cursor.execute("UPDATE livros SET disponivel = FALSE WHERE id = %s;", (livro_id,))
        conn.commit()

        # registrar interação para o dono do livro (se existir dono)
        cursor.execute("SELECT dono_id, titulo FROM livros WHERE id=%s;", (livro_id,))
        dono_row = cursor.fetchone()
        if dono_row and dono_row[0]:
            registrar_interacao(dono_row[0], 'emprestimo', f"Seu livro '{dono_row[1]}' foi emprestado.")

        return jsonify({"mensagem": "Empréstimo registrado com sucesso!"}), 201
    except Exception as e:
        conn.rollback()
        print("[Emprestimo] Erro:", e)
        return jsonify({"erro": "Erro ao registrar empréstimo."}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


# ===============================================================
# ROTAS DE DEVOLUÇÃO E LISTAGEM DE EMPRÉSTIMOS
# ===============================================================

@app.route('/emprestimos', methods=['GET'])
@login_required
def listar_emprestimos(usuario_logado):
    """ Lista os empréstimos feitos PELO usuário logado """
    usuario_id = usuario_logado['id']
    conn = conectar_banco()
    if not conn:
        return jsonify({"erro": "Erro de conexão"}), 500
    cursor = None
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT e.id, e.livro_id, e.usuario_id, e.data_emprestimo, e.data_devolucao, l.titulo AS titulo_livro
            FROM emprestimos e
            JOIN livros l ON e.livro_id = l.id
            WHERE e.usuario_id = %s
            ORDER BY e.data_emprestimo DESC;
        """, (usuario_id,))
        rows = cursor.fetchall()
        emprestimos = []
        for r in rows:
            emprestimos.append({
                'id': r[0],
                'livro_id': r[1],
                'usuario_id': r[2],
                'data_emprestimo': r[3].isoformat() if r[3] else None,
                'data_devolucao': r[4].isoformat() if r[4] else None,
                'titulo_livro': r[5]
            })
        return jsonify(emprestimos)
    except Exception as e:
        print("[Emprestimos] Erro ao listar:", e)
        return jsonify({"erro": "Erro ao listar empréstimos"}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


@app.route('/emprestimos/<int:id>/devolver', methods=['PUT'])
@login_required
def devolver_livro(usuario_logado, id):
    """
    Permite que o usuário logado devolva um livro emprestado por ele.
    'id' aqui é o ID do EMPRÉSTIMO.
    """
    usuario_id = usuario_logado['id']
    conn = conectar_banco()
    if not conn:
        return jsonify({"erro": "Erro de conexão"}), 500
    cursor = None
    try:
        cursor = conn.cursor()
        # Verifica se o empréstimo pertence ao usuário
        cursor.execute("SELECT livro_id, usuario_id, data_devolucao FROM emprestimos WHERE id=%s;", (id,))
        emprestimo = cursor.fetchone()
        if not emprestimo:
            return jsonify({"erro": "Empréstimo não encontrado."}), 404
        if emprestimo[1] != usuario_id:
            return jsonify({"erro": "Você não pode devolver um livro que não pegou emprestado."}), 403
        if emprestimo[2]:
            return jsonify({"erro": "Este livro já foi devolvido."}), 400

        # Marca devolução e torna o livro disponível novamente
        cursor.execute("UPDATE emprestimos SET data_devolucao = CURRENT_TIMESTAMP WHERE id = %s;", (id,))
        cursor.execute("UPDATE livros SET disponivel = TRUE WHERE id = %s;", (emprestimo[0],))
        conn.commit()

        # Notifica o dono do livro
        cursor.execute("SELECT dono_id, titulo FROM livros WHERE id=%s;", (emprestimo[0],))
        dono_row = cursor.fetchone()
        if dono_row and dono_row[0]:
            registrar_interacao(dono_row[0], 'devolucao', f"O livro '{dono_row[1]}' foi devolvido.")

        return jsonify({"mensagem": "Livro devolvido com sucesso!"})
    except Exception as e:
        conn.rollback()
        print("[Devolucao] Erro:", e)
        return jsonify({"erro": "Erro ao processar devolução."}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


# -----------------------
# ROTAS: FEEDBACKS
# -----------------------
@app.route('/feedback', methods=['POST'])
@login_required
def enviar_feedback(usuario_logado):
    dados = request.get_json() or {}
    livro_id = dados.get('livro_id'); nota = dados.get('nota'); comentario = dados.get('comentario')
    if not all([livro_id, nota, comentario]):
        return jsonify({"erro": "Campos obrigatórios faltando."}), 400
    conn = conectar_banco()
    if not conn: return jsonify({"erro": "Erro de conexão"}), 500
    cursor = None
    try:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO feedbacks (livro_id, usuario_id, nota, comentario)
            VALUES (%s, %s, %s, %s);
        """, (livro_id, usuario_logado['id'], nota, comentario))
        conn.commit()

        # Notificar o dono do livro (se existir)
        cursor.execute("SELECT dono_id, titulo FROM livros WHERE id=%s;", (livro_id,))
        dono = cursor.fetchone()
        if dono and dono[0]:
            registrar_interacao(dono[0], 'feedback', f"Seu livro '{dono[1]}' recebeu um novo feedback!")

        return jsonify({"mensagem": "Feedback enviado com sucesso!"}), 201
    except Exception as e:
        conn.rollback()
        print("[Feedback] Erro:", e)
        return jsonify({"erro": "Erro ao salvar feedback."}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

@app.route('/feedback', methods=['GET'])
def listar_feedbacks():
    conn = conectar_banco()
    if not conn: return jsonify({"erro": "Erro de conexão"}), 500
    cursor = None
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT f.id, u.nome, f.nota, f.comentario, f.livro_id, f.data_envio
            FROM feedbacks f
            JOIN usuarios u ON f.usuario_id = u.id
            ORDER BY f.id DESC;
        """)
        rows = cursor.fetchall()
        result = []
        for r in rows:
            result.append({
                'id': r[0],
                'nome_usuario': r[1],
                'nota': r[2],
                'comentario': r[3],
                'livro_id': r[4],
                'timestamp': r[5].isoformat() if r[5] else None
            })
        return jsonify(result)
    except Exception as e:
        print("[Feedback] Erro ao listar:", e)
        return jsonify({"erro": "Erro ao listar feedbacks"}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

# -----------------------
# ROTAS: INTERAÇÕES (NOTIFICAÇÕES)
# -----------------------
@app.route('/interacoes', methods=['GET'])
@login_required
def listar_interacoes(usuario_logado):
    usuario_id = usuario_logado['id']
    conn = conectar_banco()
    if not conn: return jsonify({"erro": "Erro de conexão"}), 500
    cursor = None
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, tipo, mensagem, timestamp, lida
            FROM interacoes
            WHERE usuario_id = %s
            ORDER BY timestamp DESC;
        """, (usuario_id,))
        rows = cursor.fetchall()
        interacoes = []
        for r in rows:
            interacoes.append({
                'id': r[0],
                'tipo': r[1],
                'mensagem': r[2],
                'timestamp': r[3].isoformat() if r[3] else None,
                'lida': bool(r[4])
            })
        return jsonify(interacoes)
    except Exception as e:
        print("[Interacoes] Erro ao listar:", e)
        return jsonify({"erro": "Erro ao listar interações"}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

@app.route('/interacoes/<int:id_interacao>/lida', methods=['PUT'])
@login_required
def marcar_interacao_lida(id_interacao, usuario_logado):
    usuario_id = usuario_logado['id']
    conn = conectar_banco()
    if not conn: return jsonify({"erro": "Erro de conexão"}), 500
    cursor = None
    try:
        cursor = conn.cursor()
        cursor.execute("UPDATE interacoes SET lida = TRUE WHERE id = %s AND usuario_id = %s;", (id_interacao, usuario_id))
        conn.commit()
        if cursor.rowcount == 0:
            return jsonify({"erro": "Interação não encontrada."}), 404
        return jsonify({"mensagem": "Interação marcada como lida."})
    except Exception as e:
        conn.rollback()
        print("[Interacoes] Erro:", e)
        return jsonify({"erro": "Erro ao marcar como lida."}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

# -----------------------
# SOCKET.IO: CHAT E NOTIFICAÇÕES
# -----------------------
@socketio.on('connect')
def socket_connect():
    print(f"[Socket] Cliente conectado: {request.sid}")

@socketio.on('disconnect')
def socket_disconnect():
    print(f"[Socket] Cliente desconectado: {request.sid}")

@socketio.on('entrar_sala')
def socket_entrar_sala(data):
    sala = data.get('sala')
    if sala:
        join_room(sala)
        print(f"[Socket] {request.sid} entrou na sala {sala}")

@socketio.on('enviar_mensagem')
def socket_enviar_mensagem(data):
    """
    Espera dados: { sala, remetente_id, remetente, texto, destinatario_id (opcional) }
    Salva no DB e emite para a sala.
    """
    sala = data.get('sala')
    texto = data.get('texto')
    remetente_id = data.get('remetente_id')
    destinatario_id = data.get('destinatario_id') 
    if not sala or not texto or not remetente_id:
        return
    conn = conectar_banco()
    cursor = None
    try:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO mensagens (sala_id, remetente_id, texto) VALUES (%s, %s, %s);",
                       (sala, remetente_id, texto))
        conn.commit()
    except Exception as e:
        conn.rollback()
        print("[Socket] Erro ao salvar mensagem:", e)
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

    # Emite para a sala
    emit('nova_mensagem', data, to=sala)

    # Registra interação para destinatário se informado
    if destinatario_id:
        registrar_interacao(destinatario_id, 'chat', f"Nova mensagem de {data.get('remetente', 'alguém')}")

# -----------------------
# RUN
# -----------------------
if __name__ == '__main__':
    print("Iniciando servidor Flask + Socket.IO na porta 5000...")
    # Usar eventlet ou gevent é recomendado para Socket.IO
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
