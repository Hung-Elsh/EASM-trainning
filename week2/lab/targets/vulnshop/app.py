# Deliberately vulnerable shop for the lab: SQLi, XSS, path traversal, no CSRF token,
# weak cookies, default Basic auth, leaked files. All data is fake. Never expose it.
import os
import sqlite3

from flask import Flask, Response, make_response, request

app = Flask(__name__)
BASE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pages")
GUESTBOOK = []

db = sqlite3.connect(":memory:", check_same_thread=False)
db.executescript("""
CREATE TABLE products (id INTEGER, name TEXT, price REAL);
INSERT INTO products VALUES (1, 'Keyboard', 25.0), (2, 'Mouse', 12.5);
CREATE TABLE users (id INTEGER, username TEXT, password TEXT);
INSERT INTO users VALUES (1, 'admin', 'admin'), (2, 'alice', 'password123');
""")


def page(title, body):
    return (f"<!DOCTYPE html><html><head><title>{title}</title></head><body>"
            f"<h1>{title}</h1>{body}</body></html>")


@app.route("/")
def index():
    response = make_response(page("SecLab Shop", """
        <!-- TODO remove: database backup server is 10.20.30.40, login admin/admin -->
        <ul>
          <li><a href="/product?id=1">Keyboard</a></li>
          <li><a href="/product?id=2">Mouse</a></li>
          <li><a href="/search?q=mouse">Search</a></li>
          <li><a href="/page?file=welcome.txt">Welcome</a></li>
          <li><a href="/guestbook">Guestbook</a></li>
          <li><a href="/login">Login</a></li>
          <li><a href="/admin">Admin</a></li>
        </ul>"""))
    # session cookie without HttpOnly, Secure or SameSite
    response.set_cookie("sessionid", "fake-session-1234")
    return response


@app.route("/product")
def product():
    # SQL injection: the parameter goes straight into the query, and errors are shown
    query = f"SELECT name, price FROM products WHERE id = {request.args.get('id', '1')}"
    try:
        rows = db.execute(query).fetchall()
    except sqlite3.Error as e:
        return page("Database error", f"<pre>You have an error in your SQL syntax: {e}\nQuery: {query}</pre>")
    return page("Product", "".join(f"<p>{name}: {price}</p>" for name, price in rows))


@app.route("/search")
def search():
    # Reflected XSS: input is returned without escaping
    return page("Search", f"<p>Results for: {request.args.get('q', '')}</p>")


@app.route("/page")
def read_page():
    # Path traversal: "../" isn't filtered (limited to this container's files)
    try:
        with open(os.path.join(BASE_DIR, request.args.get("file", "welcome.txt"))) as f:
            return page("Page", f"<pre>{f.read()}</pre>")
    except OSError as e:
        return page("Error", f"<pre>{e}</pre>"), 404


@app.route("/guestbook", methods=["GET", "POST"])
def guestbook():
    # Stored XSS: comments are saved and shown without escaping
    if request.method == "POST":
        GUESTBOOK.append(request.form.get("comment", ""))
    comments = "".join(f"<p>{comment}</p>" for comment in GUESTBOOK[-20:])
    return page("Guestbook", f"""<form method="post" action="/guestbook">
        <input type="text" name="comment"><input type="submit" value="Post"></form>{comments}""")


@app.route("/login", methods=["GET", "POST"])
def login():
    # No CSRF token, and credentials are sent over plain HTTP
    message = ""
    if request.method == "POST":
        row = db.execute("SELECT id FROM users WHERE username = ? AND password = ?",
                         (request.form.get("username"), request.form.get("password"))).fetchone()
        message = "<p>Welcome back</p>" if row else "<p>Invalid login</p>"
    return page("Login", f"""{message}<form method="post" action="/login">
        <input type="text" name="username"><input type="password" name="password">
        <input type="submit" value="Login"></form>""")


@app.route("/admin")
def admin():
    # Default credentials admin/admin
    auth = request.authorization
    if not auth or auth.username != "admin" or auth.password != "admin":
        return Response("Authentication required", 401,
                        {"WWW-Authenticate": 'Basic realm="SecLab Admin"'})
    return page("Admin", "<p>Fake admin panel</p>")


@app.route("/robots.txt")
def robots():
    return Response("User-agent: *\nDisallow: /admin\nDisallow: /.env\n", mimetype="text/plain")


@app.route("/.env")
def env_file():
    return Response("DB_HOST=10.20.30.40\nDB_PASSWORD=fake-changeme\nAPI_KEY=fake-0000\n",
                    mimetype="text/plain")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
