DEBUG = False
SQLALCHEMY_DATABASE_URI = 'mysql+mysqldb://root:7frzqt6n@127.0.0.1:3306/lms_prod'
SQLALCHEMY_TRACK_MODIFICATIONS = False
SECRET_KEY = 'super-secret-prod-key'
SESSION_COOKIE_SECURE = True
REMEMBER_COOKIE_SECURE = True
CURRENT_TEMPLATE_VERSION = 2

MAIL_SERVER = 'smtp.yourprovider.com'
MAIL_PORT = 465
MAIL_USE_TLS = False
MAIL_USE_SSL = True
MAIL_USERNAME = 'production@example.com'
MAIL_PASSWORD = 'securepassword'
MAIL_DEFAULT_SENDER = 'production@example.com'

BASE_URL = 'https://yourdomain.com/'
