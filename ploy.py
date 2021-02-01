from flask import Flask, request, Response
from flask_sqlalchemy import SQLAlchemy
from tabulate import tabulate

import hmac
import hashlib
import json
from pathlib import Path


app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite3"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = True
db = SQLAlchemy(app)


GITHUB_HOOKS_SITE_KEY = "test"
GITHUB_HOOKS_SITE_PATH = "../site"
GITHUB_HOOKS_SITE_REF = "refs/heads/deploy"


class Deployment(db.Model):
    """A deployment to keep track of."""

    identifier = db.Column(db.String(64), primary_key=True, unique=True)
    description = db.Column(db.Text, default="")

    key = db.Column(db.Text)
    events = db.Column(db.JSON)
    refs = db.Column(db.JSON)
    script = db.Column(db.JSON)


@app.route("/hook/<identifier>", methods=("POST",))
def hook(identifier: str) -> Response:
    """Invoked for any GitHub hook."""

    deployment = Deployment.query.filter_by(identifier=identifier).first()
    if deployment is None:
        return Response(status=404, mimetype="text/plain")

    verification = hmac.new(deployment.key.encode(), request.body, hashlib.sha1).hexdigest()
    offered_verification = request.headers.get("X-Hub-Signature")[len("sha1="):]
    if not hmac.compare_digest(offered_verification, verification):
        return Response(status=404, mimetype="text/plain")

    if request.headers.get("X-GitHub-Event") != deployment.events:
        return Response(status=404, mimetype="text/plain")

    data = json.loads(request.body.decode())
    if data["ref"] != settings.GITHUB_HOOKS_SITE_REF:
        return Response(status=404, mimetype="text/plain")

    log = [
        run("git", "pull", cwd=settings.GITHUB_HOOKS_SITE_PATH).dump(),
        run("bundle", "exec", "jekyll", "build", cwd=settings.GITHUB_HOOKS_SITE_PATH).dump()]

    with Path(settings.GITHUB_HOOKS_SITE_PATH, "rebuild.log.json").open("w") as file:
        json.dump(log, file)

    return HttpResponse(status=200)


if __name__ == "__main__":
    from argparse import ArgumentParser

    parser = ArgumentParser()
    command_parser = parser.add_subparsers(dest="command")
    command_parser.add_parser("database")
    command_parser.add_parser("list")
    create_parser = command_parser.add_parser("create")
    create_parser.add_argument("identifier")
    create_parser.add_argument("-d", "--description")
    create_parser.add_argument("-k", "--key", required=True)
    create_parser.add_argument("-e", "--events", nargs="+", default=["push"])
    create_parser.add_argument("-r", "--refs", nargs="+", default=["refs/heads/deploy"])
    create_parser.add_argument("script", nargs="+")

    args = parser.parse_args()
    if args.command == "database":
        db.create_all()
    elif args.command == "list":
        table = []
        for deployment in Deployment.query.all():
            table.append([
                deployment.identifier,
                deployment.description,
                ", ".join(deployment.events),
                ", ".join(deployment.refs),
                " ".join(deployment.script)])
        print(tabulate(table, headers=["Identifier", "Description", "Events", "Refs", "Script"]))
    elif args.command == "create":
        deployment = Deployment(
            identifier=args.identifier,
            key=args.key,
            events=args.events,
            refs=args.refs,
            script=args.script)
        db.session.add(deployment)
        db.session.commit()
