from flask import render_template

from . import dashboard_blueprint


@dashboard_blueprint.route("/")
def dashboard():
    return render_template("dashboard.html")
