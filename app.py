from flask import Flask, jsonify, request
from langchain_groq import ChatGroq
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
    get_jwt,
)
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta, datetime
from functools import wraps
import os
import json
import requests

from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", "sqlite:///admin_dashboard.db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = os.environ.get(
    "JWT_SECRET_KEY", "dev-secret-key-CHANGE-IN-PRODUCTION"
)
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=15)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=7)

db = SQLAlchemy(app)
jwt = JWTManager(app)
CORS(app, resources={r"/api/*": {"origins": "*"}})


# DB Schema
# -------------
class Role(db.Model):
    __tablename__ = "roles"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    users = db.relationship("User", backref="role", lazy=True)

    def to_dict(self):
        return {"id": self.id, "name": self.name}


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey("roles.id"), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role.name,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat(),
        }


class TokenBlocklist(db.Model):
    """Stores revoked JTIs so logout is immediate."""

    __tablename__ = "token_blocklist"
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


# JWT handlers
# ------------
@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    return db.session.query(TokenBlocklist.id).filter_by(jti=jti).scalar() is not None


@jwt.revoked_token_loader
def revoked_token_callback(jwt_header, jwt_payload):
    return jsonify({"error": "Token has been revoked", "code": "TOKEN_REVOKED"}), 401


@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({"error": "Token has expired", "code": "TOKEN_EXPIRED"}), 401


@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({"error": "Invalid token", "code": "INVALID_TOKEN"}), 422


@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({"error": "Authorization required", "code": "MISSING_TOKEN"}), 401


# RBAC
# ------
def role_required(*roles):
    """Decorator: restrict endpoint to users with one of the given roles."""

    def decorator(fn):
        @wraps(fn)
        @jwt_required()
        def wrapper(*args, **kwargs):
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            if not user:
                return jsonify({"error": "User not found"}), 404
            if user.role.name not in roles:
                return jsonify(
                    {
                        "error": f"Access denied. Required role(s): {', '.join(roles)}",
                        "code": "FORBIDDEN",
                    }
                ), 403
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def admin_required(fn):
    return role_required("Admin")(fn)


# Auth Routes
# ------------
@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        return jsonify({"error": "Invalid credentials"}), 401
    if not user.is_active:
        return jsonify({"error": "Account is disabled"}), 403

    additional_claims = {"role": user.role.name, "username": user.username}
    access_token = create_access_token(
        identity=user.id, additional_claims=additional_claims
    )
    refresh_token = create_refresh_token(identity=user.id)

    return jsonify(
        {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": user.to_dict(),
        }
    )


@app.route("/api/auth/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    identity = get_jwt_identity()
    user = User.query.get(identity)
    if not user:
        return jsonify({"error": "User not found"}), 404

    additional_claims = {"role": user.role.name, "username": user.username}
    access_token = create_access_token(
        identity=identity, additional_claims=additional_claims
    )
    return jsonify({"access_token": access_token})


@app.route("/api/auth/logout", methods=["DELETE"])
@jwt_required()
def logout():
    jti = get_jwt()["jti"]
    db.session.add(TokenBlocklist(jti=jti))
    db.session.commit()
    return jsonify({"message": "Successfully logged out"})


@app.route("/api/auth/me", methods=["GET"])
@jwt_required()
def me():
    user = User.query.get(get_jwt_identity())
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify(user.to_dict())


@app.route("/api/dashboard/stats", methods=["GET"])
@jwt_required()
def dashboard_stats():
    total_users = User.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    admin_count = User.query.join(Role).filter(Role.name == "Admin").count()
    viewer_count = User.query.join(Role).filter(Role.name == "Viewer").count()
    return jsonify(
        {
            "total_users": total_users,
            "active_users": active_users,
            "inactive_users": total_users - active_users,
            "admin_count": admin_count,
            "viewer_count": viewer_count,
        }
    )


@app.route("/api/users", methods=["GET"])
@jwt_required()
def get_users():
    """All authenticated users can list users."""
    users = User.query.order_by(User.created_at.desc()).all()
    return jsonify([u.to_dict() for u in users])


@app.route("/api/users", methods=["POST"])
@admin_required
def create_user():
    data = request.get_json(silent=True) or {}
    required = ["username", "email", "password", "role"]
    missing = [f for f in required if not data.get(f)]
    if missing:
        return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400

    role = Role.query.filter_by(name=data["role"]).first()
    if not role:
        return jsonify({"error": f"Role '{data['role']}' does not exist"}), 400

    if User.query.filter_by(username=data["username"]).first():
        return jsonify({"error": "Username already taken"}), 409
    if User.query.filter_by(email=data["email"]).first():
        return jsonify({"error": "Email already registered"}), 409

    user = User(username=data["username"], email=data["email"], role=role)
    user.set_password(data["password"])
    db.session.add(user)
    db.session.commit()
    return jsonify(user.to_dict()), 201


@app.route("/api/users/<int:user_id>", methods=["GET"])
@jwt_required()
def get_user(user_id):
    user = User.query.get_or_404(user_id)
    return jsonify(user.to_dict())


@app.route("/api/users/<int:user_id>", methods=["PUT"])
@admin_required
def update_user(user_id):
    user = User.query.get_or_404(user_id)
    data = request.get_json(silent=True) or {}

    if "role" in data:
        role = Role.query.filter_by(name=data["role"]).first()
        if not role:
            return jsonify({"error": f"Role '{data['role']}' does not exist"}), 400
        user.role = role

    if "is_active" in data:
        user.is_active = bool(data["is_active"])
    if "email" in data and data["email"]:
        existing = User.query.filter_by(email=data["email"]).first()
        if existing and existing.id != user_id:
            return jsonify({"error": "Email already in use"}), 409
        user.email = data["email"]
    if "password" in data and data["password"]:
        user.set_password(data["password"])

    db.session.commit()
    return jsonify(user.to_dict())


@app.route("/api/users/<int:user_id>", methods=["DELETE"])
@admin_required
def delete_user(user_id):
    # Prevent self-deletion
    current_user_id = get_jwt_identity()
    if user_id == current_user_id:
        return jsonify({"error": "You cannot delete your own account"}), 400

    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": f"User '{user.username}' deleted successfully"})


@app.route("/api/roles", methods=["GET"])
@jwt_required()
def get_roles():
    roles = Role.query.all()
    return jsonify([r.to_dict() for r in roles])


@app.route("/api/gen-comment", methods=["POST"])
# @jwt_required()
def get_ai_comments():
    payload = request.get_json(silent=True) or {}
    payload_body = json.loads(payload["body"])
    # print(payload)
    url = payload_body["url"]
    method = payload_body["method"]
    req_body = payload_body["body"]

    headers = {"Accept": "application/json"}

    data = None
    if method.upper() != "GET":
        headers["Content-Type"] = "application/json"
        # Ensure req_body is a JSON string
        if req_body is not None:
            if isinstance(req_body, (dict, list)):
                data = json.dumps(req_body)
            else:
                data = req_body

    response = requests.request(
        method=method.upper(),
        url=url,
        headers=headers,
        data=data,
        timeout=10,
    )

    content_type = response.headers.get("Content-Type", "")
    # if "application/json" in content_type:
    result_data = response.json()
    prompt = f"""
generate proper comments from supplied json or xml payload.
*CRITICAL INSTRUCTIONS*:
return the output only as JSON without any markdown tags like ```json
Inputs:
{json.dumps(result_data, indent=4)}
Output format:
{{
            "available_fields": *list of all the available fields*,
            "comments": [
                            {{
                                "field_name": "name of the filed",
                                "comment": "Comment regarding that filed"
                            }}
            ]
}}
"""

    # else:
    #     result_data = response.text

    llm = ChatGroq(model="openai/gpt-oss-120b", temperature=0, max_tokens=None)
    messages = [("system", prompt)]

    response = llm.invoke(messages)

    return {"ok": True, "status": 200, "data": response.content}


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Resource not found"}), 404


@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method not allowed"}), 405


@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "Internal server error"}), 500


# DB Initialization
# -----------------
def init_db():
    with app.app_context():
        db.create_all()

        for role_name in ["Admin", "Viewer"]:
            if not Role.query.filter_by(name=role_name).first():
                db.session.add(Role(name=role_name))
        db.session.commit()

        # default admin user
        if not User.query.filter_by(username="admin").first():
            admin_role = Role.query.filter_by(name="Admin").first()
            admin = User(username="admin", email="admin@example.com", role=admin_role)
            admin.set_password("admin123")
            db.session.add(admin)

        # default viewer user
        if not User.query.filter_by(username="viewer").first():
            viewer_role = Role.query.filter_by(name="Viewer").first()
            viewer = User(
                username="viewer", email="viewer@example.com", role=viewer_role
            )
            viewer.set_password("viewer123")
            db.session.add(viewer)

        db.session.commit()
        print("Database initialized with default users:")


#if __name__ == "__main__":
#    init_db()
#    app.run(debug=True, port=5000)
