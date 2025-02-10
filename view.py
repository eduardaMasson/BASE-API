from flask import Flask, jsonify, request
from main import app, con
from flask_bcrypt import generate_password_hash, check_password_hash
import re

#para senha com caracteres especiais
def validar_senha(senha):
    resultado = re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[@#$%^&+=]).{8,}$', senha)

    if resultado:
        return True
    else:
        return False

@app.route('/livro', methods=['GET'])
def livro():
    cur = con.cursor()
    cur.execute("SELECT id_livro, titulo, autor, ano_publicacao FROM livros")
    livros = cur.fetchall()
    livros_dic = []
    for livro in livros:
        livros_dic.append({
            'id_livro': livro[0],
            'titulo': livro[1],
            'autor': livro[2],
            'ano_publicacao': livro[3]
        })
    return jsonify(mensagem='Lista de livros', livros=livros_dic)



@app.route('/livro', methods=['POST'])
def livro_post():
    data = request.get_json()
    titulo = data.get('titulo')
    autor = data.get('autor')
    ano_publicacao = data.get('ano_publicacao')

    cursor = con.cursor()

    cursor .execute("SELECT 1 FROM LIVROS WHERE TITULO = ?", (titulo,))

    if cursor.fetchone():
        return jsonify("Livro já cadastrado!")

    cursor.execute("INSERT INTO LIVROS(TITULO, AUTOR, ANO_PUBLICACAO) VALUES (?, ?, ?)", (titulo, autor, ano_publicacao))

    con.commit()
    cursor.close()

    return jsonify({
        'message': "Livro cadastrado com sucesso!",
        'livro': {
            'titulo': titulo,
            'autor': autor,
            'ano_publicacao': ano_publicacao
        }
    })


@app.route('/livro/<int:id>', methods=['PUT'])
def livro_put(id):
    cursor = con.cursor()
    cursor.execute("select id_livro, titulo, autor, ano_publicacao from livros WHERE id_livro = ?", (id,))
    livro_data = cursor.fetchone()

    if not livro_data:
        cursor.close()
        return jsonify({"error": "Livro não foi encontrado!"}),404

    data = request.get_json()
    titulo = data.get('titulo')
    autor = data.get('autor')
    ano_publicacao = data.get('ano_publicacao')

    cursor.execute("update livros set titulo = ? , autor = ?, ano_publicacao = ? where id_livro = ?", (titulo,autor,ano_publicacao, id))

    con.commit()
    cursor.close()

    return jsonify({
        'message': "Livro atualizado com sucesso!",
        'Livro': {
            'id_livro': id,
            'titulo': titulo,
            'autor': autor,
            'ano_publicacao': ano_publicacao
        }
    })

@app.route('/livros/<int:id>', methods=['DELETE'])
def deletar_livro(id):
    cursor = con.cursor()

    # Verificar se o livro existe
    cursor.execute("SELECT 1 FROM livros WHERE ID_LIVRO = ?", (id,))
    if not cursor.fetchone():
        cursor.close()
        return jsonify({"error": "Livro não encontrado"}), 404

    # Excluir o livro
    cursor.execute("DELETE FROM livros WHERE ID_LIVRO = ?", (id,))
    con.commit()
    cursor.close()

    return jsonify({
        'message': "Livro excluído com sucesso!",
        'id_livro': id
    })


@app.route('/usuario', methods=['GET'])
def usuario():
    cur = con.cursor()
    cur.execute("SELECT id_usuario, nome, email, senha FROM usuarios")
    usuarios = cur.fetchall()
    usuarios_dic = []
    for usuario in usuarios:
        usuarios_dic.append({
            'id_usuario': usuario[0],
            'nome': usuario[1],
            'email': usuario[2],
            'senha': usuario[3]
        })
    return jsonify(mensagem='Lista de usuários', usuarios=usuarios_dic)

@app.route('/usuario', methods=['POST'])
def usuario_post():
    data = request.get_json()
    nome = data.get('nome')
    email = data.get('email')
    senha = data.get('senha')

    if not validar_senha(senha):
        return jsonify({"error": "A senha deve conter pelo menos 8 caracteres, uma letra maiúscula, uma minúscula, um número e um caractere especial."}), 400

    senha = generate_password_hash(senha).decode('utf-8')

    cursor = con.cursor()

    cursor.execute("SELECT 1 FROM usuarios WHERE email = ?", (email,))
    if cursor.fetchone():
        return jsonify({"error": "Email já cadastrado!"}), 400

    cursor.execute("INSERT INTO usuarios (nome, email, senha) VALUES (?, ?, ?)", (nome, email, senha))
    con.commit()
    cursor.close()

    return jsonify({
        'message': "Usuário cadastrado com sucesso!",
        'usuario': {
            'nome': nome,
            'email': email
        }
    })


@app.route('/usuarios/<int:id>', methods=['PUT'])
def atualizar_usuario(id):
    data = request.get_json()
    nome = data.get('nome')
    email = data.get('email')
    senha = data.get('senha')

    if senha and not validar_senha(senha):
        return jsonify({"error": "A senha deve ter pelo menos 8 caracteres, uma letra maiúscula, uma minúscula, um número e um caractere especial."}), 400

    cursor = con.cursor()
    cursor.execute("SELECT 1 FROM usuarios WHERE id_usuario = ?", (id,))
    if not cursor.fetchone():
        cursor.close()
        return jsonify({"error": "Usuário não encontrado!"}), 404

    if senha:
        cursor.execute("UPDATE usuarios SET nome = ?, email = ?, senha = ? WHERE id_usuario = ?",
                       (nome, email, senha, id))
    else:
        cursor.execute("UPDATE usuarios SET nome = ?, email = ? WHERE id_usuario = ?", (nome, email, id))

    con.commit()
    cursor.close()

    return jsonify({"message": "Usuário atualizado com sucesso!"})



@app.route('/usuarios/<int:id>', methods=['DELETE'])
def excluir_usuario(id):
    cursor = con.cursor()
    cursor.execute("SELECT 1 FROM usuarios WHERE id_usuario = ?", (id,))
    if not cursor.fetchone():
        cursor.close()
        return jsonify({"error": "Usuário não encontrado!"}), 404

    cursor.execute("DELETE FROM usuarios WHERE id_usuario = ?", (id,))
    con.commit()
    cursor.close()

    return jsonify({"message": "Usuário excluído com sucesso!"})



@app.route('/login', methods=['GET', 'POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    senha = data.get('senha')

    cursor = con.cursor()
    cursor.execute("SELECT senha FROM usuarios WHERE email = ?", (email,))
    senha_banco = cursor.fetchone()

    if not senha_banco:
        cursor.close()
        return jsonify({'message': "Login não encontrado..."})

    senha_hash = senha_banco[0]

    if check_password_hash(senha_hash, senha):
        return jsonify({
            'message': " Login feito com sucesso!"
        })
    else:
        return jsonify({"error": "Usuário ou senha incorretos!"}),404