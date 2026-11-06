# Bilerek açıklı demo hedefi — çalıştırmayın.
import subprocess
import requests
from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host")
    out = subprocess.run(
        "ping -c 1 " + host,
        shell=True,
        capture_output=True,
    )
    return out.stdout


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    return render_template_string("Merhaba " + name)


@app.route("/fetch")
def fetch():
    url = request.args["url"]
    return requests.get(url, verify=False).text


@app.route("/admin/stats")
def stats():
    return "gizli istatistikler"


@app.route("/login", methods=["POST"])
def login():
    return "ok"


if __name__ == "__main__":
    app.run(debug=True)
