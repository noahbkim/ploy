from flask import Flask, request, Response
from flask_sqlalchemy import SQLAlchemy
from tabulate import tabulate

import hmac
import hashlib
import json
import subprocess
import datetime
import timeit
from pathlib import Path


app = Flask(__name__)

database_path = Path("db.sqlite3")
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{database_path}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = True
db = SQLAlchemy(app)


GITHUB_HOOKS_SITE_KEY = "test"
GITHUB_HOOKS_SITE_PATH = "../site"
GITHUB_HOOKS_SITE_REF = "refs/heads/deploy"


class Target(db.Model):
    """A target to keep track of."""

    id = db.Column(db.String(64), primary_key=True)
    description = db.Column(db.Text, default="")
    enabled = db.Column(db.Boolean, default=True)

    key = db.Column(db.Text)
    events = db.Column(db.JSON)
    refs = db.Column(db.JSON)
    args = db.Column(db.JSON)
    timeout = db.Column(db.Integer, nullable=True)

    def execute(self) -> "Deployment":
        """Run the process and return the deployment object."""

        deployment = Deployment(target_id=self.id, start_time=datetime.datetime.now())

        try:
            process = subprocess.Popen(
                args=self.args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
        except OSError as error:
            deployment.raised_exception = True
            deployment.exception = f"operating system error: {error}"
            return deployment
        except ValueError:
            deployment.raised_exception = True
            deployment.exception = "failed to open process"
            return deployment
        except subprocess.SubprocessError as exception:
            deployment.raised_exception = True
            deployment.exception = f"subprocess error: {exception}"
            return deployment

        start = timeit.default_timer()
        try:
            stdout, stderr = process.communicate(timeout=self.timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            deployment.timed_out = True
            deployment.timeout = self.timeout
            deployment.elapsed_time = timeit.default_timer() - start
            return deployment

        deployment.stdout = stdout.decode(errors="replace")
        deployment.stderr = stderr.decode(errors="replace")
        deployment.status = process.returncode
        deployment.elapsed_time = timeit.default_timer() - start

        return deployment


class Deployment(db.Model):
    """Details from executing target arguments."""

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    target_id = db.Column(db.String(64), db.ForeignKey(Target.id))

    start_time = db.Column(db.DateTime)
    elapsed_time = db.Column(db.Float)

    timed_out = db.Column(db.Boolean, default=False)
    timeout = db.Column(db.Integer, nullable=True, default=None)

    raised_exception = db.Column(db.Boolean, default=False)
    exception = db.Column(db.Text, nullable=True, default=None)

    stdout = db.Column(db.Text, nullable=True, default=None)
    stderr = db.Column(db.Text, nullable=True, default=None)
    status = db.Column(db.Integer, nullable=True, default=None)

    target = db.relationship("Target", foreign_keys="Deployment.target_id")


@app.route("/hook/<id>", methods=("POST",))
def hook(id: str) -> Response:
    """Invoked for any GitHub hook."""

    target = Target.query.filter_by(id=id).first()
    if target is None:
        return Response(status=404, mimetype="text/plain")

    verification = hmac.new(target.key.encode(), request.body, hashlib.sha1).hexdigest()
    offered_verification = request.headers.get("X-Hub-Signature")[len("sha1="):]
    if not hmac.compare_digest(offered_verification, verification):
        return Response(status=404, mimetype="text/plain")

    if request.headers.get("X-GitHub-Event") != target.events:
        return Response(status=204, mimetype="text/plain")

    data = json.loads(request.body.decode())
    if data["ref"] not in target.refs:
        return Response(status=204, mimetype="text/plain")

    deployment = target.execute()
    db.session.add(deployment)
    db.session.commit()

    return Response(status=200, mimetype="text/plain")


def main():
    import shlex
    from argparse import ArgumentParser

    parser = ArgumentParser()
    command_parser = parser.add_subparsers(dest="command")

    # Database tools
    database_parser = command_parser.add_parser("database")
    database_command_parser = database_parser.add_subparsers(dest="database_command")
    database_command_parser.add_parser("create")

    # Target tools
    target_parser = command_parser.add_parser("target")
    target_command_parser = target_parser.add_subparsers(dest="target_command")
    target_command_parser.add_parser("list")
    target_create_parser = target_command_parser.add_parser("create")
    target_create_parser.add_argument("id")
    target_create_parser.add_argument("-d", "--description")
    target_create_parser.add_argument("-k", "--key", required=True)
    target_create_parser.add_argument("-e", "--events", nargs="+", default=["push"])
    target_create_parser.add_argument("-r", "--refs", nargs="+", default=["refs/heads/deploy"])
    target_create_parser.add_argument("-t", "--timeout", type=float, default=None)
    target_create_parser.add_argument("args", nargs="+")

    # Deployment tools
    deployment_parser = command_parser.add_parser("deployment")
    deployment_command_parser = deployment_parser.add_subparsers(dest="deployment_command")
    deployment_list_parser = deployment_command_parser.add_parser("list")
    deployment_list_parser.add_argument("-n", "--count", default=10)
    deployment_list_parser.add_argument("-t", "--target")

    args = parser.parse_args()

    # Migrate
    if args.command == "database":
        if database_path.exists():
            if not input("database already exists, delete? [Y/n] ").lower().strip().startswith("y"):
                return
            db.drop_all()
        db.create_all()

    # Target tools
    elif args.command == "target":

        # List targets
        if args.target_command == "list":
            table = []
            for target in Target.query.all():
                table.append([
                    target.id,
                    target.description,
                    ", ".join(target.events),
                    ", ".join(target.refs),
                    shlex.join(target.args)])
            print(tabulate(table, headers=["Id", "Description", "Events", "Refs", "Args"]))

        # Create a new target
        elif args.target_command == "create":
            target = Target(
                id=args.id,
                key=args.key,
                events=args.events,
                refs=args.refs,
                args=args.args,
                timeout=args.timeout)
            db.session.add(target)
            db.session.commit()

    # Deployment tools
    elif args.command == "deployment":

        # List deployments
        if args.deployment_command == "list":
            table = []
            for deployment in Deployment.query.all():
                table.append([
                    deployment.target_id,
                    str(deployment.start_time),
                    str(deployment.elapsed_time),
                    deployment.raised_exception,
                    deployment.timed_out,
                    deployment.status])
            print(tabulate(table, headers=["Target", "Time", "Elapsed", "Except", "Timeout", "Status"]))


if __name__ == "__main__":
    main()
