import psycopg2
from psycopg2 import Error

def conectar_banco():
    try:
        conexao = psycopg2.connect(
            host="localhost",
            database="biblioteca",
            user="postgres",
            password="decarli123"
        )
        print("Conexão com o PostgreSQL realizada com sucesso!")
        return conexao
    except (Exception, Error) as error:
        print(f"Erro ao conectar ao PostgreSQL: {error}")
        return None

def inserir_livro(conexao, titulo, autor, ano_publicacao, genero):
    try:
        cursor = conexao.cursor()
        sql = "INSERT INTO livros (titulo, autor, ano_publicacao, genero) VALUES (%s, %s, %s, %s);"
        cursor.execute(sql, (titulo, autor, ano_publicacao, genero))
        conexao.commit()
        print(f"\n>>> Livro '{titulo}' inserido com sucesso! <<<")
    except (Exception, Error) as error:
        print(f"Erro ao inserir dados: {error}")
    finally:
        if cursor:
            cursor.close()

def listar_livros(conexao):
    try:
        cursor = conexao.cursor()
        cursor.execute("SELECT id, titulo, autor, ano_publicacao, genero FROM livros ORDER BY id;")
        registros = cursor.fetchall()
        
        if not registros:
            print("\n--- Catálogo de Livros ---")
            print("Nenhum livro encontrado.")
            print("--------------------------\n")
            return

        print("\n--- Catálogo de Livros ---")
        for linha in registros:
            print(f"ID: {linha[0]} | Título: {linha[1]}, Autor: {linha[2]}, Ano: {linha[3]}")
        print("--------------------------\n")
    except (Exception, Error) as error:
        print(f"Erro ao consultar dados: {error}")
    finally:
        if cursor:
            cursor.close()

def deletar_livro(conexao, id_livro):
    try:
        cursor = conexao.cursor()
        sql = "DELETE FROM livros WHERE id = %s;"
        cursor.execute(sql, (id_livro,))
        conexao.commit()
        
        if cursor.rowcount > 0:
            print(f"\n>>> Livro com ID {id_livro} deletado com sucesso! <<<")
        else:
            print(f"\n>>> Nenhum livro encontrado com o ID {id_livro}. Nada foi deletado. <<<")
    except (Exception, Error) as error:
        print(f"Erro ao deletar dados: {error}")
    finally:
        if cursor:
            cursor.close()

# --- DEFINIÇÃO DA FUNÇÃO MAIN (DEPOIS DAS FUNÇÕES QUE ELA USA) ---

def main():
    # Aqui, conectar_banco() JÁ FOI DEFINIDA
    conn = conectar_banco() 
    if not conn:
        print("Não foi possível conectar ao banco de dados. O programa será encerrado.")
        return

    while True:
        print("\n--- Menu Principal da Biblioteca ---")
        print("1. Listar livros")
        print("2. Adicionar novo livro")
        print("3. Deletar um livro")
        print("4. Sair do programa")
        print("5. Buscar livro por título") # Adicionado no exemplo anterior
        
        escolha = input("Escolha uma opção (1-5): ")

        if escolha == '1':
            listar_livros(conn)
        
        elif escolha == '2':
            print("\n--- Adicionar Novo Livro ---")
            titulo = input("Digite o título: ")
            autor = input("Digite o autor: ")
            
            while True:
                try:
                    ano = int(input("Digite o ano de publicação: "))
                    break
                except ValueError:
                    print("Ano inválido. Por favor, digite apenas números.")
            
            genero = input("Digite o gênero: ")
            inserir_livro(conn, titulo, autor, ano, genero)

        elif escolha == '3':
            print("\n--- Deletar um Livro ---")
            listar_livros(conn)
            
            while True:
                try:
                    id_para_deletar = int(input("Digite o ID do livro que deseja deletar: "))
                    break
                except ValueError:
                    print("ID inválido. Por favor, digite apenas números.")
            
            deletar_livro(conn, id_para_deletar)

        elif escolha == '4':
            print("\nSaindo...")
            break

        elif escolha == '5':
            termo = input("Digite o termo para buscar no título: ")
            # Lembre-se de adicionar a função buscar_livro_por_titulo aqui se não adicionou
            # buscar_livro_por_titulo(conn, termo) 
            print("Função de busca não implementada neste exemplo completo, adicione-a acima!") # Temporário
            
        else:
            print("\nOpção inválida! Por favor, escolha um número de 1 a 5.")

    conn.close()
    print("Conexão com o PostgreSQL foi encerrada.")

# --- INÍCIO DA EXECUÇÃO (SEM MUITO RECUO) ---
if __name__ == "__main__":
    main()