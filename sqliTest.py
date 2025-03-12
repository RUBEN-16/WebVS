from flask import Flask, request, render_template_string, redirect
import sqlite3

app = Flask(__name__)

# 🛠️ Create database and users table (if not exists)
def init_db():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

# 🌟 Add a test user (for login testing)
def add_test_user():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (username, password) VALUES ('admin', 'password123')")
    conn.commit()
    conn.close()

# 🌐 HTML template for login page
HTML_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Vulnerable Login</title>
</head>
<body>
    <h2>Login Page</h2>
    <form method="POST" action="/login">
        <input type="text" name="username" placeholder="Username" required>
        <input type="password" name="password" placeholder="Password" required>
        <button type="submit">Login</button>
    </form>
</body>
</html>
"""

@app.route("/")
def home():
    return render_template_string(HTML_PAGE)

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    # 🚨 VULNERABLE SQL QUERY (PRONE TO SQL INJECTION) 🚨
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    
    print(f"🔍 Executing SQL Query: {query}")  # Debugging purposes

    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()

    if user:
        return "✅ Login Successful!"
    else:
        return "❌ Invalid Credentials!"

if __name__ == "__main__":
    init_db()
    add_test_user()
    app.run(debug=True)
