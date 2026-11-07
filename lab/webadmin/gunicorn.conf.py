# Make gunicorn present itself as Apache so scanners don't see "gunicorn".
import gunicorn

gunicorn.SERVER = "Apache/2.4.57 (Debian)"
gunicorn.SERVER_SOFTWARE = gunicorn.SERVER
