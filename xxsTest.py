from flask import Flask, request, render_template_string

app = Flask(__name__)

# Vulnerable XSS page
HTML_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>XSS Test Page</title>
</head>
<body>
    <h2>XSS Vulnerability Test</h2>
    <form method="POST">
        Enter your name: <input type="text" name="name"><br>
        <input type="submit" value="Submit">
    </form>
    <p>{{ message}}</p>
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def xss_test():
    message = ""
    if request.method == "POST":
        name = request.form.get("name", "")
        # Reflect the user input directly (vulnerable to XSS)
        message = f"Hello, {name}!"

    return render_template_string(HTML_PAGE, message=message)

if __name__ == "__main__":
    app.run(debug=True)