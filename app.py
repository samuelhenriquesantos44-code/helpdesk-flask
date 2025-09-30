from __future__ import annotations
from datetime import datetime
import os
import sqlite3
from pathlib import Path
from typing import Optional
from urllib.parse import quote  # para montar ?next= no login_required

from flask import (
    Flask, g, redirect, render_template_string, request, session, url_for, flash
)
from werkzeug.security import generate_password_hash, check_password_hash
from jinja2 import DictLoader

# -----------------------------------------------------
# Config
# -----------------------------------------------------
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "dev-secret-change-me"),
    DATABASE=str(Path(__file__).with_name("helpdesk.db")),
)

# -----------------------------------------------------
# DB
# -----------------------------------------------------
SCHEMA_SQL = r"""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'cliente',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'aberto',
    department TEXT,
    subcategory TEXT,
    user_id INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(ticket_id) REFERENCES tickets(id),
    FOREIGN KEY(user_id) REFERENCES users(id)
);
"""

DEPT_MAP = {
    "Suporte": ["Hardware", "Software", "Acesso/Senha", "Impressoras"],
    "Infra": ["Rede/Wi-Fi", "Servidores", "Backup", "VPN"],
    "Sistemas": ["ERP", "CRM", "BI/Relatórios", "Integrações"],
    "Financeiro": ["NF/Boletos", "Pagamentos", "Cadastro Fornecedor"],
}

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def _column_exists(table: str, name: str) -> bool:
    db = get_db()
    cur = db.execute(f"PRAGMA table_info({table})")
    return any(row[1] == name for row in cur.fetchall())

def init_db():
    db = get_db()
    db.executescript(SCHEMA_SQL)
    db.commit()

    # Migrações leves (para quem veio de versões antigas)
    if not _column_exists("users", "role"):
        db.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'cliente'")
        db.commit()
    if not _column_exists("tickets", "department"):
        db.execute("ALTER TABLE tickets ADD COLUMN department TEXT")
        db.commit()
    if not _column_exists("tickets", "subcategory"):
        db.execute("ALTER TABLE tickets ADD COLUMN subcategory TEXT")
        db.commit()

    # Usuário admin semente
    cur = db.execute("SELECT 1 FROM users WHERE email = ?", ("admin@local",))
    if cur.fetchone() is None:
        db.execute(
            "INSERT INTO users (name, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
            ("Administrador", "admin@local", generate_password_hash("admin123"), "admin", datetime.utcnow().isoformat()),
        )
        db.commit()

# -----------------------------------------------------
# Auth helpers
# -----------------------------------------------------
def current_user() -> Optional[sqlite3.Row]:
    uid = session.get("user_id")
    if not uid:
        return None
    db = get_db()
    cur = db.execute("SELECT id, name, email, role, created_at FROM users WHERE id = ?", (uid,))
    return cur.fetchone()

def login_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            nxt = quote(request.path or "/")
            # usar literal /login evita quebrar se endpoint mudar
            return redirect(f"/login?next={nxt}")
        return fn(*args, **kwargs)
    return wrapper

def admin_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user or user["role"] != "admin":
            flash("Acesso restrito ao admin.", "danger")
            return redirect(url_for("index"))
        return fn(*args, **kwargs)
    return wrapper

# -----------------------------------------------------
# Templates (UI + Sidebar híbrida)
# -----------------------------------------------------
BASE_HTML = r"""
<!doctype html>
<html lang="pt-br">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ title or 'Help Desk' }}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
    <style>
      :root {
        --bg: #f8fafc;
        --card: #ffffff;
        --muted: #64748b;
        --primary: #0ea5e9;
        --primary-dark: #0284c7;
        --ring: #bae6fd;
        --sidebar: #ffffff;
        --sidebar-border: #e2e8f0;
      }
      body { background: var(--bg); color: #0f172a; }
      a { text-decoration: none; }

      /* Layout com sidebar fixa em >=992px */
      @media (min-width: 992px) {
        .layout {
          display: grid;
          grid-template-columns: 240px 1fr;
          gap: 0;
          min-height: 100vh;
        }
        .sidebar {
          position: sticky;
          top: 0;
          height: 100vh;
          padding: 1rem;
          border-right: 1px solid var(--sidebar-border);
          background: linear-gradient(180deg,#fff,#f8fafc);
        }
        .main {
          padding: 1rem 1.25rem 2rem;
        }
        .topbar { display: none; } /* esconde topbar em desktop */
      }

      /* Em <992px usamos topbar + offcanvas */
      @media (max-width: 991.98px) {
        .main { padding: 0 1rem 2rem; }
        .sidebar { display: none; } /* sidebar fixa some e usamos offcanvas */
        .topbar {
          border-bottom: 1px solid #e2e8f0;
          background: linear-gradient(180deg,#ffffff,#f8fafc);
        }
      }

      .card {
        border-radius: 16px; border: 1px solid #e2e8f0;
        box-shadow: 0 6px 24px rgba(2,132,199,.08);
      }
      .btn-primary { background: var(--primary); border-color: var(--primary); }
      .btn-primary:hover { background: var(--primary-dark); border-color: var(--primary-dark); }
      .form-control, .form-select { border-radius: 10px; }
      .badge { font-size: .85rem; }

      .hero {
        background: url('https://images.unsplash.com/photo-1556157382-97eda2d62296?q=80&w=1200&auto=format') center/cover no-repeat;
        border-radius: 18px; min-height: 180px; position: relative; overflow: hidden;
      }
      .hero::after{content:"";position:absolute;inset:0;background:linear-gradient(0deg,rgba(255,255,255,.95),rgba(255,255,255,.4));}
      .hero > .inner{position:relative; z-index:1;}
      .nav-link { color: #0f172a; }
      .nav-link.active, .nav-link:hover { color: var(--primary-dark); }
      .menu-section { font-size: .75rem; color: var(--muted); text-transform: uppercase; letter-spacing:.04em; margin: .75rem 0 .25rem; }
    </style>
  </head>
  <body>
    <!-- Topbar (mobile) -->
    <nav class="topbar navbar navbar-light px-2">
      <div class="container-fluid">
        <button class="btn btn-outline-secondary" data-bs-toggle="offcanvas" data-bs-target="#offcanvasMenu">
          ☰
        </button>
        <a class="nav-link {% if request.endpoint=='app_home' %}active{% endif %}" href="{{ url_for('app_home') }}">
          🛟 Help Desk <span class="badge bg-info text-dark ms-1">V3.2</span>
        </a>
        {% if user %}
          <a class="btn btn-outline-secondary btn-sm" href="{{ url_for('app_home') if user else url_for('index_public') }}"><i class="bi bi-person"></i></a>
        {% else %}
          <a class="btn btn-primary btn-sm" href="{{ url_for('login') }}">Entrar</a>
        {% endif %}
      </div>
    </nav>

    <!-- Offcanvas (mobile) -->
    <div class="offcanvas offcanvas-start" tabindex="-1" id="offcanvasMenu">
      <div class="offcanvas-header">
        <h5 class="offcanvas-title">Menu</h5>
        <button type="button" class="btn-close" data-bs-dismiss="offcanvas"></button>
      </div>
      <div class="offcanvas-body">
        {% include 'menu.html' %}
      </div>
    </div>

    <div class="layout">
      <!-- Sidebar fixa (desktop) -->
      <aside class="sidebar">
        <div class="d-flex align-items-center justify-content-between mb-3">
          <a class="fw-semibold h5 mb-0" href="{{ url_for('index') }}">🛟 Help Desk</a>
          <span class="badge bg-info text-dark">V3.2</span>
        </div>
        {% include 'menu.html' %}
      </aside>

      <!-- Conteúdo -->
      <main class="main container-fluid">
        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            <div class="mb-3">
              {% for cat, msg in messages %}
                <div class="alert alert-{{ 'secondary' if cat=='info' else cat }} alert-dismissible fade show" role="alert">
                  {{ msg }}
                  <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                </div>
              {% endfor %}
            </div>
          {% endif %}
        {% endwith %}
        {% block content %}{% endblock %}
      </main>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  </body>
</html>
"""

# Menu (reutilizável na sidebar fixa e no offcanvas)
MENU_HTML = r"""
<div class="menu">
  <div class="menu-section">Navegação</div>
  {% if user %}
    <ul class="nav flex-column">
      <li class="nav-item">
        <a class="nav-link {% if request.endpoint=='index' %}active{% endif %}" href="{{ url_for('index') }}">
          <i class="bi bi-speedometer2 me-2"></i>Dashboard
        </a>
      </li>
      <li class="nav-item">
        <a class="nav-link {% if request.endpoint=='tickets' %}active{% endif %}" href="{{ url_for('tickets') }}">
          <i class="bi bi-card-list me-2"></i>Meus chamados
        </a>
      </li>
      <li class="nav-item">
        <a class="nav-link {% if request.endpoint=='ticket_new' %}active{% endif %}" href="{{ url_for('ticket_new') }}">
          <i class="bi bi-plus-square me-2"></i>Abrir chamado
        </a>
      </li>
      {% if user.role=='admin' %}
      <li class="nav-item">
        <a class="nav-link {% if request.endpoint=='admin_tickets' %}active{% endif %}" href="{{ url_for('admin_tickets') }}">
          <i class="bi bi-wrench-adjustable-circle me-2"></i>Painel admin
        </a>
      </li>
      {% endif %}
    </ul>

    <div class="menu-section">Conta</div>
    <ul class="nav flex-column">
      <li class="nav-item"><a class="nav-link {% if request.endpoint=='profile' %}active{% endif %}" href="{{ url_for('profile') }}"><i class="bi bi-person-circle me-2"></i>Perfil</a></li>
      <li class="nav-item"><a class="nav-link" href="/logout"><i class="bi bi-box-arrow-right me-2"></i>Sair</a></li>
    </ul>
    <div class="mt-3 small text-muted">Olá, {{ user.name.split(' ')[0] }}{% if user.role=='admin' %} (admin){% endif %}</div>
  {% else %}
    <ul class="nav flex-column">
      <li class="nav-item"><a class="nav-link" href="/login"><i class="bi bi-box-arrow-in-right me-2"></i>Entrar</a></li>
      <li class="nav-item"><a class="nav-link" href="{{ url_for('register') }}"><i class="bi bi-person-plus me-2"></i>Criar conta</a></li>
    </ul>
  {% endif %}
</div>
"""
PUBLIC_HOME_HTML = r"""
{% extends 'base.html' %}
{% block content %}
<div class="hero mb-4 d-flex align-items-center">
  <div class="inner p-4">
    <h1 class="h3 mb-2">Quem somos</h1>
    <p class="mb-0 text-muted">Nossa história e objetivo</p>
  </div>
</div>

<div class="row g-4">
  <div class="col-12 col-lg-8">
    <div class="card p-4">
      <h2 class="h5 mb-3">Nossa história</h2>
      <p>Texto contando a história da empresa...</p>
      <h2 class="h5 mt-4 mb-3">Nosso objetivo</h2>
      <p>Texto sobre objetivo e missão...</p>
    </div>
  </div>
  <div class="col-12 col-lg-4">
    <div class="card p-4">
      <h2 class="h6">Contato</h2>
      <ul class="list-unstyled mb-0">
        <li>Email: contato@empresa.com</li>
        <li>Telefone: (11) 99999-9999</li>
      </ul>
    </div>
  </div>
</div>
{% endblock %}
"""

INDEX_HTML = r"""
{% extends 'base.html' %}
{% block content %}
  {% if user and user.role=='admin' %}
  <div class="hero mb-4 d-flex align-items-center">
    <div class="inner p-4">
      <h1 class="h3 mb-2">Painel do Administrador</h1>
      <p class="mb-0 text-muted">Resumo dos chamados da empresa.</p>
    </div>
  </div>

  <div class="row g-4 mb-4">
    <div class="col-6 col-lg-3">
      <a class="card p-3 d-block" href="{{ url_for('admin_tickets') }}?status=aberto">
        <div class="d-flex align-items-center gap-2"><i class="bi bi-patch-question-fill"></i><span>Abertos</span></div>
        <div class="display-6">{{ kpis.open }}</div>
      </a>
    </div>
    <div class="col-6 col-lg-3">
      <a class="card p-3 d-block" href="{{ url_for('admin_tickets') }}?status=em%20andamento">
        <div class="d-flex align-items-center gap-2"><i class="bi bi-hourglass-split"></i><span>Em andamento</span></div>
        <div class="display-6">{{ kpis.progress }}</div>
      </a>
    </div>
    <div class="col-6 col-lg-3">
      <a class="card p-3 d-block" href="{{ url_for('admin_tickets') }}?status=fechado">
        <div class="d-flex align-items-center gap-2"><i class="bi bi-check2-circle"></i><span>Fechados</span></div>
        <div class="display-6">{{ kpis.closed }}</div>
      </a>
    </div>
    <div class="col-6 col-lg-3">
      <a class="card p-3 d-block" href="{{ url_for('admin_tickets') }}">
        <div class="d-flex align-items-center gap-2"><i class="bi bi-collection"></i><span>Total</span></div>
        <div class="display-6">{{ kpis.total }}</div>
      </a>
    </div>
  </div>
  {% else %}
  <div class="hero mb-4 d-flex align-items-center">
    <div class="inner p-4">
      <h1 class="h3 mb-2">Atendimento de TI simples e eficiente</h1>
      <p class="mb-0 text-muted">Abra, acompanhe e resolva seus chamados.</p>
    </div>
  </div>
  {% endif %}

  <div class="row g-4">
    <div class="col-12 col-lg-7">
      <div class="card p-4">
        <h2 class="h5 mb-3">Como funciona?</h2>
        <ul class="mb-0">
          <li>Abra um chamado descrevendo seu problema e selecione setor/subcategoria.</li>
          <li>Acompanhe o status e converse via comentários.</li>
          <li>{% if user and user.role=='admin' %}Como admin, veja todos os chamados no painel.{% else %}Nossa equipe atualiza o status para você.{% endif %}</li>
        </ul>
      </div>
    </div>
    <div class="col-12 col-lg-5">
      <div class="card p-4">
        <h2 class="h6">Atalhos</h2>
        <div class="d-grid gap-2">
          {% if user %}
          <a class="btn btn-primary" href="{{ url_for('ticket_new') }}">➕ Abrir chamado</a>
          <a class="btn btn-outline-secondary" href="{{ url_for('tickets') }}">📋 Meus chamados</a>
          {% if user.role=='admin' %}
          <a class="btn btn-outline-secondary" href="{{ url_for('admin_tickets') }}">🛠️ Painel admin</a>
          {% endif %}
          {% else %}
          <a class="btn btn-primary" href="/login">Entrar</a>
          <a class="btn btn-outline-secondary" href="{{ url_for('register') }}">Criar conta</a>
          {% endif %}
        </div>
      </div>
    </div>
  </div>
{% endblock %}
"""

LOGIN_HTML = r"""
{% extends 'base.html' %}
{% block content %}
<div class="row justify-content-center">
  <div class="col-12 col-md-6">
    <div class="card p-4">
      <h1 class="h4 mb-3">Entrar</h1>
      <form method="post">
        <div class="mb-3">
          <label class="form-label">E-mail</label>
          <input class="form-control" type="email" name="email" required>
        </div>
        <div class="mb-3">
          <label class="form-label">Senha</label>
          <input class="form-control" type="password" name="password" required>
        </div>
        <button class="btn btn-primary" type="submit">Entrar</button>
      </form>
      <p class="mt-3 mb-0">Não tem conta? <a href="{{ url_for('register') }}">Cadastre-se</a>.</p>
    </div>
  </div>
</div>
{% endblock %}
"""

REGISTER_HTML = r"""
{% extends 'base.html' %}
{% block content %}
<div class="row justify-content-center">
  <div class="col-12 col-md-7 col-lg-6">
    <div class="card p-4">
      <h1 class="h4 mb-3">Criar conta</h1>
      <form method="post">
        <div class="mb-3">
          <label class="form-label">Nome</label>
          <input class="form-control" type="text" name="name" required>
        </div>
        <div class="mb-3">
          <label class="form-label">E-mail</label>
          <input class="form-control" type="email" name="email" required>
        </div>
        <div class="mb-3">
          <label class="form-label">Senha</label>
          <input class="form-control" type="password" name="password" minlength="6" required>
        </div>
        <button class="btn btn-primary" type="submit">Criar</button>
      </form>
      <p class="mt-3 mb-0">Já possui conta? <a href="/login">Entrar</a>.</p>
    </div>
  </div>
</div>
{% endblock %}
"""

PROFILE_HTML = r"""
{% extends 'base.html' %}
{% block content %}
<div class="row justify-content-center">
  <div class="col-12 col-lg-8">
    <div class="card p-4">
      <h1 class="h5 mb-3">Meu perfil</h1>

      <form method="post" action="{{ url_for('profile_update_name') }}" class="mb-4">
        <h2 class="h6">Alterar nome</h2>
        <div class="row g-2 align-items-end">
          <div class="col-md-8">
            <label class="form-label">Nome</label>
            <input class="form-control" type="text" name="name" value="{{ user.name }}" required>
          </div>
          <div class="col-md-4">
            <button class="btn btn-primary w-100" type="submit">Salvar</button>
          </div>
        </div>
      </form>

      <form method="post" action="{{ url_for('profile_update_password') }}">
        <h2 class="h6">Alterar senha</h2>
        <div class="row g-2">
          <div class="col-md-4">
            <label class="form-label">Senha atual</label>
            <input class="form-control" type="password" name="current" required>
          </div>
          <div class="col-md-4">
            <label class="form-label">Nova senha</label>
            <input class="form-control" type="password" name="new" minlength="6" required>
          </div>
          <div class="col-md-4">
            <label class="form-label">Confirmar nova senha</label>
            <input class="form-control" type="password" name="new2" minlength="6" required>
          </div>
        </div>
        <div class="mt-3">
          <button class="btn btn-primary" type="submit">Atualizar senha</button>
        </div>
      </form>
    </div>
  </div>
</div>
{% endblock %}
"""

TICKETS_HTML = r"""
{% extends 'base.html' %}
{% block content %}
<div class="d-flex justify-content-between align-items-center mb-3">
  <h1 class="h4">Meus chamados</h1>
  <a class="btn btn-primary" href="{{ url_for('ticket_new') }}">➕ Abrir chamado</a>
</div>

{% if tickets %}
  <div class="row g-3">
  {% for t in tickets %}
    <div class="col-12">
      <div class="card p-3 d-flex flex-md-row align-items-md-center justify-content-between">
        <div>
          <div class="d-flex align-items-center gap-2">
            <a class="h5 mb-1" href="{{ url_for('ticket_view', ticket_id=t.id) }}">#{{ t.id }} — {{ t.title }}</a>
            <span class="badge {{ 'bg-success' if t.status=='fechado' else ('bg-warning text-dark' if t.status=='em andamento' else 'bg-secondary') }}">{{ t.status|capitalize }}</span>
          </div>
          <div class="text-muted small">{{ t.department }}{% if t.subcategory %} · {{ t.subcategory }}{% endif %}</div>
          <div class="text-muted small">Aberto em {{ t.created_at[:19].replace('T',' ') }}</div>
        </div>
        <div>
          <a class="btn btn-outline-secondary btn-sm" href="{{ url_for('ticket_view', ticket_id=t.id) }}">Detalhes</a>
        </div>
      </div>
    </div>
  {% endfor %}
  </div>
{% else %}
  <div class="card p-4"><em>Você ainda não abriu chamados.</em></div>
{% endif %}
{% endblock %}
"""

TICKET_NEW_HTML = r"""
{% extends 'base.html' %}
{% block content %}
<div class="row justify-content-center">
  <div class="col-12 col-lg-8">
    <div class="card p-4">
      <h1 class="h4 mb-3">Abrir chamado</h1>
      <form method="post">
        <div class="mb-3">
          <label class="form-label">Título</label>
          <input class="form-control" type="text" name="title" maxlength="120" required>
        </div>
        <div class="row g-3">
          <div class="col-md-6">
            <label class="form-label">Setor</label>
            <select class="form-select" name="department" id="department" required>
              <option value="" selected disabled>Selecione</option>
              {% for d in dept_options %}
                <option value="{{ d }}">{{ d }}</option>
              {% endfor %}
            </select>
          </div>
          <div class="col-md-6">
            <label class="form-label">Subcategoria</label>
            <select class="form-select" name="subcategory" id="subcategory" required disabled>
              <option value="" selected>Selecione o setor primeiro</option>
            </select>
          </div>
        </div>
        <div class="mb-3 mt-3">
          <label class="form-label">Descrição</label>
          <textarea class="form-control" name="description" rows="6" required></textarea>
        </div>
        <button class="btn btn-primary" type="submit">Criar chamado</button>
        <a class="btn btn-outline-secondary ms-2" href="{{ url_for('tickets') }}">Cancelar</a>
      </form>
    </div>
  </div>
</div>

<script>
const MAP = {{ dept_map|tojson }};
const deptSel = document.getElementById('department');
const subSel = document.getElementById('subcategory');
if (deptSel) {
  deptSel.addEventListener('change', () => {
    const list = MAP[deptSel.value] || [];
    subSel.innerHTML = '';
    if (list.length === 0){
      subSel.innerHTML = '<option value="">Sem opções</option>';
      subSel.disabled = true;
      return;
    }
    list.forEach(v => {
      const o = document.createElement('option');
      o.value = v; o.textContent = v; subSel.appendChild(o);
    });
    subSel.disabled = false;
  });
}
</script>
{% endblock %}
"""

TICKET_VIEW_HTML = r"""
{% extends 'base.html' %}
{% block content %}
<div class="row justify-content-center">
  <div class="col-12 col-lg-10">
    <div class="card p-4">
      <div class="d-flex justify-content-between align-items-start">
        <div>
          <h1 class="h5 mb-1">#{{ t.id }} — {{ t.title }}</h1>
          <div class="text-muted small">{{ t.department }}{% if t.subcategory %} · {{ t.subcategory }}{% endif %}</div>
          <div class="text-muted small">Aberto em {{ t.created_at[:19].replace('T',' ') }}</div>
        </div>
        <span class="badge {{ 'bg-success' if t.status=='fechado' else ('bg-warning text-dark' if t.status=='em andamento' else 'bg-secondary') }}">{{ t.status|capitalize }}</span>
      </div>
      <hr>
      <p class="mb-4" style="white-space: pre-wrap">{{ t.description }}</p>

      <form method="post" action="{{ url_for('ticket_update_status', ticket_id=t.id) }}" class="d-flex gap-2 mb-4">
        <select class="form-select" name="status">
          {% for s in ['aberto','em andamento','fechado'] %}
            <option value="{{ s }}" {% if t.status==s %}selected{% endif %}>{{ s|capitalize }}</option>
          {% endfor %}
        </select>
        <button class="btn btn-primary" type="submit">Atualizar status</button>
      </form>

      <h2 class="h6">Comentários</h2>
      <div class="mb-3">
        {% if comments %}
          <ul class="list-unstyled mb-0">
            {% for c in comments %}
            <li class="mb-3">
              <div class="p-3 rounded" style="background:#f1f5f9;">
                <div class="small text-muted d-flex justify-content-between">
                  <span>{{ c.name }}{% if c.role=='admin' %} (admin){% endif %}</span>
                  <span>{{ c.created_at[:19].replace('T',' ') }}</span>
                </div>
                <div style="white-space: pre-wrap;" class="mt-1">{{ c.body }}</div>
              </div>
            </li>
            {% endfor %}
          </ul>
        {% else %}
          <div class="text-muted">Ainda não há comentários.</div>
        {% endif %}
      </div>

      <form method="post" action="{{ url_for('ticket_add_comment', ticket_id=t.id) }}">
        <div class="mb-3">
          <label class="form-label">Adicionar comentário</label>
          <textarea class="form-control" name="body" rows="3" required placeholder="Descreva o que foi feito, dúvidas, etc."></textarea>
        </div>
        <button class="btn btn-primary" type="submit">Publicar</button>
      </form>
    </div>
  </div>
</div>
{% endblock %}
"""

ADMIN_TICKETS_HTML = r"""
{% extends 'base.html' %}
{% block content %}
  <div class="d-flex justify-content-between align-items-center mb-3">
    <h1 class="h4">Painel admin — Todos os chamados</h1>
  </div>
  {% if tickets %}
  <div class="table-responsive card p-2">
    <table class="table align-middle mb-0">
      <thead>
        <tr>
          <th>ID</th><th>Título</th><th>Autor</th><th>Depto</th><th>Subcat</th><th>Status</th><th>Aberto em</th><th>Ações</th>
        </tr>
      </thead>
      <tbody>
        {% for t in tickets %}
        <tr>
          <td>#{{ t.id }}</td>
          <td><a href="{{ url_for('ticket_view', ticket_id=t.id) }}">{{ t.title }}</a></td>
          <td>{{ t.author_name }} ({{ t.author_email }})</td>
          <td>{{ t.department }}</td>
          <td>{{ t.subcategory }}</td>
          <td>
            <span class="badge {{ 'bg-success' if t.status=='fechado' else ('bg-warning text-dark' if t.status=='em andamento' else 'bg-secondary') }}">{{ t.status|capitalize }}</span>
          </td>
          <td class="text-muted small">{{ t.created_at[:19].replace('T',' ') }}</td>
          <td>
            <form method="post" action="{{ url_for('ticket_update_status', ticket_id=t.id) }}" class="d-flex gap-2">
              <select class="form-select form-select-sm" name="status">
                {% for s in ['aberto','em andamento','fechado'] %}
                <option value="{{ s }}" {% if t.status==s %}selected{% endif %}>{{ s|capitalize }}</option>
                {% endfor %}
              </select>
              <button class="btn btn-primary btn-sm" type="submit">Salvar</button>
            </form>
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% else %}
    <div class="card p-4">Nenhum chamado encontrado.</div>
  {% endif %}
{% endblock %}
"""

# Registrar templates
from jinja2 import DictLoader
app.jinja_loader = DictLoader({
    'base.html': BASE_HTML,
    'index.html': INDEX_HTML,
    'login.html': LOGIN_HTML,
    'register.html': REGISTER_HTML,
    'profile.html': PROFILE_HTML,
    'tickets.html': TICKETS_HTML,
    'ticket_new.html': TICKET_NEW_HTML,
    'ticket_view.html': TICKET_VIEW_HTML,
    'admin_tickets.html': ADMIN_TICKETS_HTML,
    'public_home.html': PUBLIC_HOME_HTML,
   })
# -----------------------------------------------------
# Rotas
# -----------------------------------------------------
@app.before_request
def before_request():
    init_db()

@app.get("/")
def index_public():
    # Landing pública (sem login)
    return render_template_string(
        app.jinja_loader.get_source(app.jinja_env, "public_home.html")[0],
        user=current_user()
    )

@app.get("/app")
@login_required
def app_home():
    user = current_user()
    # KPIs só para admin
    kpis = None
    if user and user["role"] == "admin":
        def count(q, a=()):
            return get_db().execute(q, a).fetchone()[0]
        kpis = {
            "open":     count("SELECT COUNT(*) FROM tickets WHERE status='aberto'"),
            "progress": count("SELECT COUNT(*) FROM tickets WHERE status='em andamento'"),
            "closed":   count("SELECT COUNT(*) FROM tickets WHERE status='fechado'"),
            "total":    count("SELECT COUNT(*) FROM tickets"),
        }

    return render_template_string(
        app.jinja_loader.get_source(app.jinja_env, "index.html")[0],
        user=user,
        kpis=(kpis or {})
    )

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        db = get_db()
        cur = db.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cur.fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            flash("Login realizado com sucesso.", "success")
            nxt = request.args.get("next")
            return redirect(nxt or url_for("app_home"))
        flash("Credenciais inválidas.", "danger")
    return render_template_string(
        app.jinja_loader.get_source(app.jinja_env, "login.html")[0],
        user=current_user()
    )

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not name or not email or not password:
            flash("Preencha todos os campos.", "warning")
        else:
            db = get_db()
            try:
                db.execute(
                    "INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                    (name, email, generate_password_hash(password), datetime.utcnow().isoformat()),
                )
                db.commit()
                flash("Conta criada. Faça login.", "success")
                return redirect("/login")
            except sqlite3.IntegrityError:
                flash("E-mail já cadastrado.", "danger")
    return render_template_string(
        app.jinja_loader.get_source(app.jinja_env, "register.html")[0],
        user=current_user()
    )

@app.get("/logout")
@login_required
def logout():
    session.clear()
    flash("Sessão encerrada.", "info")
    return redirect("/login")

@app.get("/profile")
@login_required
def profile():
    return render_template_string(
        app.jinja_loader.get_source(app.jinja_env, "profile.html")[0],
        user=current_user()
    )

@app.post("/profile/name")
@login_required
def profile_update_name():
    name = (request.form.get("name") or "").strip()
    if not name:
        flash("Nome inválido.", "warning")
        return redirect(url_for("profile"))
    db = get_db()
    db.execute("UPDATE users SET name = ? WHERE id = ?", (name, session["user_id"]))
    db.commit()
    flash("Nome atualizado.", "success")
    return redirect(url_for("profile"))

@app.post("/profile/password")
@login_required
def profile_update_password():
    current = request.form.get("current", "")
    new = request.form.get("new", "")
    new2 = request.form.get("new2", "")
    if not new or new != new2:
        flash("Nova senha não confere.", "danger")
        return redirect(url_for("profile"))
    db = get_db()
    user = db.execute("SELECT password_hash FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    if not user or not check_password_hash(user["password_hash"], current):
        flash("Senha atual incorreta.", "danger")
        return redirect(url_for("profile"))
    db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (generate_password_hash(new), session["user_id"]))
    db.commit()
    flash("Senha atualizada.", "success")
    return redirect(url_for("profile"))

@app.get("/tickets")
@login_required
def tickets():
    db = get_db()
    status = (request.args.get('status') or '').strip()
    if status in {"aberto", "em andamento", "fechado"}:
        cur = db.execute(
            "SELECT id, title, description, status, department, subcategory, created_at FROM tickets WHERE user_id = ? AND status = ? ORDER BY id DESC",
            (session["user_id"], status),
        )
    else:
        cur = db.execute(
            "SELECT id, title, description, status, department, subcategory, created_at FROM tickets WHERE user_id = ? ORDER BY id DESC",
            (session["user_id"],),
        )
    rows = cur.fetchall()
    return render_template_string(
        app.jinja_loader.get_source(app.jinja_env, "tickets.html")[0],
        user=current_user(),
        tickets=rows
    )

@app.route("/tickets/novo", methods=["GET", "POST"])
@login_required
def ticket_new():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        desc = request.form.get("description", "").strip()
        dept = request.form.get("department", "").strip()
        subc = request.form.get("subcategory", "").strip()
        if not title or not desc or not dept or not subc:
            flash("Preencha título, setor e subcategoria.", "warning")
        else:
            db = get_db()
            db.execute(
                """
                INSERT INTO tickets (title, description, status, department, subcategory, user_id, created_at)
                VALUES (?, ?, 'aberto', ?, ?, ?, ?)
                """,
                (title, desc, dept, subc, session["user_id"], datetime.utcnow().isoformat()),
            )
            db.commit()
            flash("Chamado criado com sucesso.", "success")
            return redirect(url_for("tickets"))
    return render_template_string(
        app.jinja_loader.get_source(app.jinja_env, "ticket_new.html")[0],
        user=current_user(),
        dept_options=list(DEPT_MAP.keys()),
        dept_map=DEPT_MAP
    )

@app.get("/tickets/<int:ticket_id>")
@login_required
def ticket_view(ticket_id: int):
    db = get_db()
    user = current_user()
    if user and user["role"] == "admin":
        cur = db.execute(
            "SELECT id, title, description, status, department, subcategory, created_at FROM tickets WHERE id = ?",
            (ticket_id,),
        )
    else:
        cur = db.execute(
            "SELECT id, title, description, status, department, subcategory, created_at FROM tickets WHERE id = ? AND user_id = ?",
            (ticket_id, session["user_id"],),
        )
    t = cur.fetchone()
    if not t:
        flash("Chamado não encontrado.", "warning")
        return redirect(url_for("tickets"))

    comments = db.execute(
        """
        SELECT c.id, c.body, c.created_at, u.name, u.role
        FROM comments c JOIN users u ON u.id = c.user_id
        WHERE c.ticket_id = ? ORDER BY c.id ASC
        """,
        (ticket_id,)
    ).fetchall()

    return render_template_string(
        app.jinja_loader.get_source(app.jinja_env, "ticket_view.html")[0],
        user=current_user(),
        t=t, comments=comments
    )

@app.post("/tickets/<int:ticket_id>/status")
@login_required
def ticket_update_status(ticket_id: int):
    new_status = request.form.get("status", "aberto").strip()
    if new_status not in {"aberto", "em andamento", "fechado"}:
        flash("Status inválido.", "danger")
        return redirect(url_for("ticket_view", ticket_id=ticket_id))

    db = get_db()
    user = current_user()
    if user and user["role"] == "admin":
        db.execute("UPDATE tickets SET status = ? WHERE id = ?", (new_status, ticket_id))
    else:
        db.execute("UPDATE tickets SET status = ? WHERE id = ? AND user_id = ?", (new_status, ticket_id, session["user_id"]))
    db.commit()
    flash("Status atualizado.", "success")
    return redirect(url_for("ticket_view", ticket_id=ticket_id))

@app.post("/tickets/<int:ticket_id>/comments")
@login_required
def ticket_add_comment(ticket_id: int):
    body = (request.form.get("body") or "").strip()
    if not body:
        flash("Comentário vazio.", "warning")
        return redirect(url_for("ticket_view", ticket_id=ticket_id))

    db = get_db()
    user = current_user()
    allowed = False
    if user and user["role"] == "admin":
        allowed = True
    else:
        cur = db.execute("SELECT 1 FROM tickets WHERE id = ? AND user_id = ?", (ticket_id, session["user_id"]))
        allowed = cur.fetchone() is not None

    if not allowed:
        flash("Você não pode comentar neste chamado.", "danger")
        return redirect(url_for("tickets"))

    db.execute(
        "INSERT INTO comments (ticket_id, user_id, body, created_at) VALUES (?, ?, ?, ?)",
        (ticket_id, session["user_id"], body, datetime.utcnow().isoformat()),
    )
    db.commit()
    return redirect(url_for("ticket_view", ticket_id=ticket_id))

@app.get("/admin/tickets")
@login_required
@admin_required
def admin_tickets():
    db = get_db()
    status = (request.args.get('status') or '').strip()
    base_sql = """
        SELECT t.id, t.title, t.status, t.created_at, t.department, t.subcategory,
               u.name as author_name, u.email as author_email
        FROM tickets t JOIN users u ON u.id = t.user_id
    """
    args = []
    if status in {"aberto", "em andamento", "fechado"}:
        base_sql += " WHERE t.status = ?"
        args.append(status)
    base_sql += " ORDER BY t.id DESC"
    rows = db.execute(base_sql, tuple(args)).fetchall()
    return render_template_string(
        app.jinja_loader.get_source(app.jinja_env, "admin_tickets.html")[0],
        user=current_user(),
        tickets=rows
    )

# -----------------------------------------------------
# Execução
# -----------------------------------------------------
if __name__ == "__main__":
    Path(app.config["DATABASE"]).touch(exist_ok=True)
    with app.app_context():
        init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
