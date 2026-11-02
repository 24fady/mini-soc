import click

from .extensions import db
from .models import AdminUser
from .security import hash_password


def register_cli(app):
    @app.cli.command("init-db")
    def init_db():
        """Create all database tables."""
        db.create_all()
        click.echo("Database tables created.")

    @app.cli.command("create-admin")
    @click.option("--username", default="admin", show_default=True)
    @click.option("--password", envvar="ADMIN_PASSWORD", prompt=True,
                  hide_input=True, confirmation_prompt=True)
    def create_admin(username, password):
        """Create the dashboard administrator (bcrypt-hashed password)."""
        if len(password) < 10:
            raise click.ClickException("Password must be at least 10 characters.")
        db.create_all()
        if AdminUser.query.filter_by(username=username).first():
            click.echo(f"Admin '{username}' already exists. Nothing changed.")
            return
        db.session.add(AdminUser(username=username, password_hash=hash_password(password)))
        db.session.commit()
        click.echo(f"Admin '{username}' created.")
