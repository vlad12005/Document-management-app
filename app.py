from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def hello_world():
    return render_template("first.html")
@app.route('/sign')
def index():
    return render_template('sign.html')
@app.route('/log')
def login():
    return render_template('login.html')


if __name__ == '__main__':
    app.run(debug=True)

