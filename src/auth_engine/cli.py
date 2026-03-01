import os
import subprocess
import sys
from pathlib import Path

import typer
import uvicorn

app = typer.Typer(help="AuthEngine CLI")


def get_project_root() -> Path:
    return Path(__file__).parent.parent.parent


@app.command()
def run(
    host: str = "0.0.0.0",
    port: int = 8000,
    reload: bool = False,
) -> None:
    """
    Run the FastAPI server
    """
    # Ensure src is in PYTHONPATH
    project_root = get_project_root()
    env = os.environ.copy()
    env["PYTHONPATH"] = str(project_root / "src")

    uvicorn.run(
        "auth_engine.main:app",
        host=host,
        port=port,
        reload=reload,
    )


@app.command()
def migrate() -> None:
    """
    Run Alembic migrations
    """
    # Use the alembic executable from the virtual environment
    alembic_path = str(Path(sys.executable).parent / "alembic")
    subprocess.run([alembic_path, "upgrade", "head"])


@app.command()
def makemigration(message: str) -> None:
    """
    Create a new migration
    """
    alembic_path = str(Path(sys.executable).parent / "alembic")
    subprocess.run([alembic_path, "revision", "--autogenerate", "-m", message])


if __name__ == "__main__":
    app()
