import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix


class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)
login_manager = LoginManager()

from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman

app = Flask(__name__)
csrf = CSRFProtect(app)

csp = {
    'default-src': ["'self'"],
    'script-src': ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
    'style-src': ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://fonts.googleapis.com"],
    'font-src': ["'self'", "https://cdnjs.cloudflare.com", "https://fonts.gstatic.com"],
    'img-src': ["'self'", "data:", "https://lh3.googleusercontent.com"],
}
talisman = Talisman(app, content_security_policy=csp, force_https=False) # force_https=False because local dev might be HTTP
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.secret_key = os.environ.get("SESSION_SECRET") or os.environ.get("FLASK_SECRET_KEY") or "dev-secret-key-change-in-production"

# Database configuration: prefer DATABASE_URL, fall back to a local sqlite file for dev
db_url = os.environ.get("DATABASE_URL") or os.environ.get("SQLALCHEMY_DATABASE_URI")
if not db_url:
    # development fallback (file in project root)
    db_path = os.path.join(os.getcwd(), "data.sqlite")
    db_url = f"sqlite:///{db_path}"
    import logging
    logging.warning(f"No DATABASE_URL set, using fallback sqlite DB at {db_path}")

app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["MAX_CONTENT_LENGTH"] = 250 * 1024 * 1024

db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    from models import User
    return User.query.get(int(user_id))
