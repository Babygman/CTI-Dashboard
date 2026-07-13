from flask import Flask, render_template
from config import Config

app = Flask(__name__)
app.config.from_object(Config)


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


if __name__ == "__main__":
    app.run(debug=True)