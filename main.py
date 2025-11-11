#!/usr/bin/env python
import os
from flask import Flask, render_template, session, request, send_from_directory

from api.api import api, testset

app = Flask(__name__)
app.secret_key = b'secret'
app.register_blueprint(api)


@app.route('/favicon.ico')
def favicon():
  return send_from_directory(
      os.path.join(app.root_path, 'static'),
      'wallet.ico', mimetype='image/vnd.microsoft.icon'
  )


@app.route("/")
def main():
  return render_template("main.j2", testset=testset)


@app.route("/test", methods=['POST'])
def test():
  form = request.form
  session['form'] = form
  test_id = form.get('test_id')
  vc_type = form.get('vc_type', '_JWT')
  args = {
      'test_id': test_id,
      'vc_type': vc_type,
  }

  return render_template("test.j2", **args)


if __name__ == "__main__":
  app.run()
