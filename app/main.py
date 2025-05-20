from app import create_app
from waitress import serve
from app.utils import format_ddmmyyyy  # adjust path if needed

app = create_app()
app.jinja_env.filters['format_ddmmyyyy'] = format_ddmmyyyy

if __name__ == "__main__":
    app.run(
        #ssl_context=("C:/localhost.pem", "C:/localhost.key"),
        #host='localhost',
        #port=5000,
        debug=True
    )
