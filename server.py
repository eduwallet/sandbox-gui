#!/usr/bin/env python
import json
import random
import urllib.request as request
from flask import Flask, render_template


def randid():
    allowed_chars = 'abcdefghijklmnoprstuvwxyz1234567890'
    length = 16
    return ''.join([random.choice(allowed_chars) for n in range(length)])


def parse_tests(tests):
    body = "<pre>\n"
    for id, test in tests.items():
        # body += json.dumps(test, indent=4)
        # body += f"{id}\n"
        body += f"<a href='/{id}'>{test['name']}</a>\n"
        body += f"{test['description']}\n"
        body += f"{test['type']}\n"
        body += f"{test['spec_version']}\n\n"
    body += "</pre>\n"

    return body


app = Flask(__name__)


@app.route("/")
def server():
    return render_template("server.j2", body=body)


@app.route("/<id>")
def test(id):
    return render_template("test.j2", id=id)


@app.route("/api/get/<id>")
def api_get(id):
    test = tests[id]

    message = {
        "status": "success",
        "id": id,
        "test": test,
    }

    return json.dumps(message)


@app.route("/api/pre_authorized_code/<id>")
def api_pre_authorized_code(id):
    test = tests[id]

    pre_authorized_code = randid()
    data = {
        'credentials': [test['credential']['name']],
        'grants': {
            'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
                'pre-authorized_code': pre_authorized_code,
            },
        },
        'credentialDataSupplierInput': test['credential']['claims'],
    }

    if test['options'].get('tx_code', None):
        data['grants']['urn:ietf:params:oauth:grant-type:pre-authorized_code']['tx_code'] = True

    json_data = json.dumps(data).encode("utf-8")

    issuer_url = 'https://agent.dev.eduwallet.nl/uvh/api'
    create_url = issuer_url + "/create-offer"
    issuer_token = 'KZrytiX6RXDaXIUnstjCKyr1SRIblhWi'

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {issuer_token}"
    }

    req = request.Request(create_url, json_data, headers)
    with request.urlopen(req) as f:
        res = json.loads(f.read().decode())

    # print(res)

    qr_uri = res['uri']
    pin = res.get('txCode')

    message = {
        "status": "success",
        "id": id,
        "test": test,
        "qr_uri": qr_uri,
        "pin": pin,
        "pac": pre_authorized_code,
        "data": data
    }

    return json.dumps(message)


@app.route("/api/pac_status/<pac>")
def pac_status(pac):
    data = {
        'id': pac
    }

    json_data = json.dumps(data).encode("utf-8")

    issuer_url = 'https://agent.dev.eduwallet.nl/uvh/api'
    check_url = issuer_url + "/check-offer"

    headers = {
        "Content-Type": "application/json",
    }

    req = request.Request(check_url, json_data, headers)
    with request.urlopen(req) as f:
        res = json.loads(f.read().decode())

    # print(res)

    status = res['status']
    return json.dumps(status)


@app.route("/api/verifier/<id>")
def verifier(id):
    test = tests[id]

    data = {}
    json_data = json.dumps(data).encode("utf-8")

    verifier_url = 'https://verifier.dev.eduwallet.nl/proxy/api'
    create_url = verifier_url + "/create-offer/" + test['credential']['name']
    verifier_token = 'PElLibogkyc3cBUBvYRSMK7q4yThXYwM'

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {verifier_token}"
    }

    req = request.Request(create_url, json_data, headers)
    with request.urlopen(req) as f:
        res = json.loads(f.read().decode())

    # print(res)

    qr_uri = res['requestUri']
    check_uri = res['checkUri']
    code = check_uri.split("/")[-1]

    message = {
        "status": "success",
        "id": id,
        "test": test,
        "qr_uri": qr_uri,
        "code": code
    }

    return json.dumps(message)


@app.route("/api/verifier_status/<code>")
def verifier_status(code):
    check_url = f'https://verifier.dev.eduwallet.nl/proxy/api/check-offer/{code}'
    verifier_token = 'PElLibogkyc3cBUBvYRSMK7q4yThXYwM'

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {verifier_token}"
    }

    req = request.Request(check_url, None, headers)
    with request.urlopen(req) as f:
        res = json.loads(f.read().decode())

    # print(res)

    status = res['status']
    result = res.get('result')

    message = {
        "status": status,
        "result": result
    }

    return json.dumps(message)


with open('tests.json') as data:
    tests = json.load(data)
    body = parse_tests(tests)


if __name__ == "__main__":
    app.run()
