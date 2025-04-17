from app import create_app
from waitress import serve

app = create_app()

if __name__ == "__main__":
    app.run(
        #ssl_context=("C:/localhost.pem", "C:/localhost.key"),
        #host='localhost',
        #port=5000,
        debug=True
    )