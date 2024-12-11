from dash import Dash, dcc, html, Input, Output, State
import dash_bootstrap_components as dbc
import sqlite3
from flask import session
from werkzeug.security import generate_password_hash, check_password_hash  # Importa as funções de hash

from home import layout

# Inicializa a aplicação Dash
app = Dash(__name__, suppress_callback_exceptions=True, external_stylesheets=[dbc.themes.BOOTSTRAP])
app.title = "Login e Registro"
server = app.server

server.secret_key = "sua_chave_secreta_segura_aqui"

# Função para inicializar o banco de dados
def init_db():
    conn = sqlite3.connect("usuarios.db")
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
    """)
    conn.commit()
    conn.close()

init_db()

# Funções para manipulação de usuários no banco de dados
def registrar_usuario(username, password):
    # Criptografa a senha antes de armazená-la
    hashed_password = generate_password_hash(password)
    
    conn = sqlite3.connect("usuarios.db")
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO usuarios (username, password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False  # Usuário já existe
    finally:
        conn.close()

def verificar_usuario(username, password):
    conn = sqlite3.connect("usuarios.db")
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM usuarios WHERE username = ?", (username,))
    usuario = cursor.fetchone()
    conn.close()
    
    if usuario is not None:
        # Verifica se a senha fornecida corresponde ao hash armazenado
        return check_password_hash(usuario[0], password)
    return False

# Layouts (não alterados)
login_layout = dbc.Container(
    [
        dbc.Row(dbc.Col(html.H2("Login", className="text-center"))),
        dbc.Row(
            dbc.Col(
                dbc.Form(
                    [
                        html.Div(
                            [
                                dbc.Label("Usuário", html_for="login-username"),
                                dbc.Input(id="login-username", type="text", placeholder="Digite seu usuário"),
                            ],
                            className="mb-3",
                        ),
                        html.Div(
                            [
                                dbc.Label("Senha", html_for="login-password"),
                                dbc.Input(id="login-password", type="password", placeholder="Digite sua senha"),
                            ],
                            className="mb-3",
                        ),
                        html.Div(
                            dbc.Button("Entrar", id="login-button", color="primary", className="w-100"),
                            className="d-grid gap-2",
                        ),
                        html.Div(id="login-alert", className="text-danger mt-3"),
                        html.Div(
                            dcc.Link("Não tem uma conta? Registre-se ", href="/registro"),
                            className="text-center mt-3",
                        ),
                    ]
                ),
                width=4,
            ),
            justify="center",
        ),
    ],
    className="mt-5",
)

registro_layout = dbc.Container(
    [
        dbc.Row(dbc.Col(html.H2("Registro", className="text-center"))),
        dbc.Row(
            dbc.Col(
                dbc.Form(
                    [
                        html.Div(
                            [
                                dbc.Label("Usuário", html_for="registro-username"),
                                dbc.Input(id="registro-username", type="text", placeholder="Escolha um usuário"),
                            ],
                            className="mb-3",
                        ),
                        html.Div(
                            [
                                dbc.Label("Senha", html_for="registro-password"),
                                dbc.Input(id="registro-password", type="password", placeholder="Escolha uma senha"),
                            ],
                            className="mb-3",
                        ),
                        html.Div(
                            [
                                dbc.Label("Confirme a Senha", html_for="registro-password-confirm"),
                                dbc.Input(
                                    id="registro-password-confirm",
                                    type="password",
                                    placeholder="Repita a senha",
                                ),
                            ],
                            className="mb-3",
                        ),
                        html.Div(
                            dbc.Button("Registrar", id="registro-button", color="success", className="w-100"),
                            className="d-grid gap-2",
                        ),
                        html.Div(id="registro-alert", className="text-danger mt-3"),
                        html.Div(
                            dcc.Link("Já tem uma conta? Faça login aqui.", href="/login"),
                            className="text-center mt-3",
                        ),
                    ]
                ),
                width=4,
            ),
            justify="center",
        ),
    ],
    className="mt-5",
)



# Callbacks para ações (sem alterar page-content diretamente)
@app.callback(
    Output("login-alert", "children"),
    Input("login-button", "n_clicks"),
    State("login-username", "value"),
    State("login-password", "value"),
    prevent_initial_call=True,
)
def handle_login(n_clicks, username, password):
    if verificar_usuario(username, password):
        session["logged_in"] = True
        return dcc.Location(href="/home", id="redirect-home")
    else:
        return "Usuário ou senha inválidos."

@app.callback(
    Output("registro-alert", "children"),
    Input("registro-button", "n_clicks"),
    State("registro-username", "value"),
    State("registro-password", "value"),
    State("registro-password-confirm", "value"),
    prevent_initial_call=True,
)
def handle_registro(n_clicks, username, password, password_confirm):
    if not username or not password or not password_confirm:
        return "Preencha todos os campos."
    if password != password_confirm:
        return "As senhas não correspondem."
    if registrar_usuario(username, password):
        return dcc.Location(href="/login", id="redirect-login")
    else:
        return "Usuário já existe."

@app.callback(
    Output("url", "pathname"),
    Input("logout-button", "n_clicks"),
    prevent_initial_call=True,
)
def handle_logout(n_clicks):
    session["logged_in"] = False
    return "/login"

# Callback para roteamento
@app.callback(Output("page-content", "children"), Input("url", "pathname"))
def display_page(pathname):
    if pathname == "/registro":
        return registro_layout
    elif pathname == "/login":
        return login_layout
    elif pathname == "/home" and session.get("logged_in"):
        return layout
    else:
        return login_layout

# Layout inicial
app.layout = html.Div(
    [
        dcc.Location(id="url", refresh=False),
        html.Div(id="page-content"),
    ]
)

if __name__ == "__main__":
    app.run_server(debug=True)
