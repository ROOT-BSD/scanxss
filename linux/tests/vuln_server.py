#!/usr/bin/env python3
"""
Локальний вразливий тестовий веб-сервер для перевірки WapitiC.
УВАГА: Тільки для тестування! Не запускати у production!
"""
import http.server
import urllib.parse
import threading
import time
import sys

PORT = 8888

HTML_INDEX = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Вразливий тест-сайт</title></head>
<body>
<h1>Тестовий сайт WapitiC</h1>
<nav>
  <a href="/search">Пошук</a> |
  <a href="/login">Вхід</a> |
  <a href="/file">Файл</a> |
  <a href="/redirect?url=http://safe.example.com">Redirect</a>
</nav>
</body></html>"""

HTML_SEARCH = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Пошук</title></head>
<body>
<h2>Пошук</h2>
<form method="GET" action="/search">
  <input type="text" name="q" value="">
  <input type="submit" value="Шукати">
</form>
<form method="POST" action="/comment">
  <input type="text" name="name" value="">
  <textarea name="comment"></textarea>
  <input type="submit" value="Надіслати">
</form>
</body></html>"""

HTML_LOGIN = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Вхід</title></head>
<body>
<form method="POST" action="/login">
  <input type="text" name="username" placeholder="Логін">
  <input type="password" name="password" placeholder="Пароль">
  <input type="submit" value="Увійти">
</form>
</body></html>"""

HTML_FILE = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Файл</title></head>
<body>
<form method="GET" action="/file">
  <input type="text" name="filename" value="readme.txt">
  <input type="submit" value="Відкрити">
</form>
</body></html>"""

class VulnHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # silence default logs

    def send_html(self, code, body):
        enc = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(enc))
        self.end_headers()
        self.wfile.write(enc)

    def parse_qs(self, raw):
        return urllib.parse.parse_qs(raw or "", keep_blank_values=True)

    def read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length).decode("utf-8", errors="replace") if length else ""

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path   = parsed.path
        qs     = self.parse_qs(parsed.query)

        if path == "/":
            self.send_html(200, HTML_INDEX)

        elif path == "/search":
            q = qs.get("q", [""])[0]
            # VУLN: XSS — відображаємо q без екранування
            body = f"""<!DOCTYPE html><html><body>
<h2>Результати для: {q}</h2>
<form method="GET" action="/search">
  <input name="q" value="{q}">
  <input type="submit" value="Шукати">
</form>
</body></html>"""
            self.send_html(200, body)

        elif path == "/file":
            fname = qs.get("filename", ["readme.txt"])[0]
            # VULN: LFI — читаємо файл за параметром
            try:
                with open(fname, "r") as f:
                    content = f.read()
            except PermissionError:
                content = "Permission denied"
            except Exception:
                # емулюємо passwd при traversal
                if "passwd" in fname or "etc" in fname:
                    content = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                else:
                    content = "Файл не знайдено"
            body = f"<pre>{content}</pre>"
            self.send_html(200, body)

        elif path == "/redirect":
            url = qs.get("url", ["/"])[0]
            # VULN: Open Redirect
            self.send_response(302)
            self.send_header("Location", url)
            self.end_headers()

        elif path == "/login":
            self.send_html(200, HTML_LOGIN)

        else:
            self.send_html(404, "<h1>404 Not Found</h1>")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path   = parsed.path
        body   = self.read_body()
        params = self.parse_qs(body)

        if path == "/login":
            user = params.get("username", [""])[0]
            pwd  = params.get("password", [""])[0]
            # VULN: SQLi — емулюємо DB error при спецсимволах
            if "'" in user or '"' in user or "--" in user:
                resp = f"""<html><body>
<b>Warning: mysql_fetch_array()</b> expects parameter 1...
You have an error in your SQL syntax near '{user}'
</body></html>"""
            else:
                resp = f"<html><body>Невірний логін для: {user}</body></html>"
            self.send_html(200, resp)

        elif path == "/comment":
            name    = params.get("name",    [""])[0]
            comment = params.get("comment", [""])[0]
            # VULN: Stored-style XSS reflection
            resp = f"""<html><body>
<h3>Коментар від {name}:</h3>
<p>{comment}</p>
</body></html>"""
            self.send_html(200, resp)

        else:
            self.send_html(404, "<h1>404</h1>")


def run(stop_event):
    server = http.server.HTTPServer(("127.0.0.1", PORT), VulnHandler)
    server.timeout = 0.5
    print(f"[TestServer] Слухає на http://127.0.0.1:{PORT}/")
    while not stop_event.is_set():
        server.handle_request()
    server.server_close()
    print("[TestServer] Зупинено")


if __name__ == "__main__":
    stop = threading.Event()
    t = threading.Thread(target=run, args=(stop,), daemon=True)
    t.start()
    try:
        duration = int(sys.argv[1]) if len(sys.argv) > 1 else 120
        time.sleep(duration)
    except KeyboardInterrupt:
        pass
    stop.set()
    t.join(timeout=2)
