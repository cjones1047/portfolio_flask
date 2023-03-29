from flask import Flask, render_template
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
import decouple

app = Flask(__name__)
app.config['SECRET_KEY'] = decouple.config('SECRET_KEY')
ckeditor = CKEditor(app)
Bootstrap(app)


@app.route('/')
def index():
    return render_template("index.html")


# set port based on development vs production environment
# set debug status based on presence of DATABASE_URL env variable
server_port = int(decouple.config("PORT", 8000))

if decouple.config("DATABASE_URL", False):
    debug_status = False
else:
    debug_status = True

if __name__ == "__main__":
    app.run(port=server_port, debug=debug_status)
