#!/usr/bin/env python
import json
import urllib.request
import logging
import ssl
from flask import Blueprint, session
from api import testset, config

api = Blueprint("api", __name__, url_prefix="/api")

context = ssl._create_unverified_context()


@api.route("/get_test")
def get_test():
  form = session.get('form')
  if form is None:
    logging.error("get_test request failed")
    message = {
        "status": "error"
    }
    return json.dumps(message)

  test_file = form.get('test_file')
  if test_file != "free":
    test_id = form.get('test_id')
    test = testset[test_file][test_id]
  else:
    test = {
        "agent": "issuer",
        "credential": form.get('free', {})
    }

  message = {
      "status": "success",
      "test": test,
  }

  # print(message)
  return json.dumps(message)


@api.route("/pre_authorized_code")
def pre_authorized_code():
  form = session.get('form')
  if form is None:
      logging.error("pre_authorized_code request failed")
      message = {
          "status": "error"
      }
      return json.dumps(message)

  test_file = form.get('test_file')
  vc_type = form.get('vc_type')
  if test_file != "free":
    test_id = form.get('test_id')
    test = testset[test_file][test_id]
  else:
    test = {
        "agent": "issuer",
        "credential": json.loads(form.get('free', {}))
    }

  credential_type = test['type']
  if credential_type in [
      'GenericCredential',
      # 'SupportCredential',
      # 'StudyDataCredential',
      # 'StudentCardCredential',
      # 'ExamEnrollmentCredential'
  ]:
    pass
  credential_type += vc_type

  data = {
      'credentials': [credential_type],
      'grants': {
          'urn:ietf:params:oauth:grant-type:pre-authorized_code': {},
      },
      'credentialDataSupplierInput': test['credential'],
  }

  tx_code_len = form.get('tx_code_len')
  if int(tx_code_len) > 0:
    tx_code_mode = form.get('tx_code_mode')
    tx_code = {
        'length': int(tx_code_len),
        'input_mode': tx_code_mode
    }
  else:
    tx_code = False

  data['grants']['urn:ietf:params:oauth:grant-type:pre-authorized_code']['tx_code'] = tx_code

  json_data = json.dumps(data).encode("utf-8")

  create_url = config['issuer']['url'] + "/create-offer"

  headers = {
      "Content-Type": "application/json",
      "Authorization": f"Bearer {config['issuer']['token']}"
  }

  # print(f'create_url: {create_url}')
  # print(headers)
  # print(json_data)

  req = urllib.request.Request(create_url, json_data, headers)
  with urllib.request.urlopen(req, context=context) as f:
    res = json.loads(f.read().decode())

  qr_uri = res['uri']
  pin = res.get('txCode')
  pac_id = res.get('id')

  message = {
      "status": "success",
      "test": test,
      "qr_uri": qr_uri,
      "pin": pin,
      "data": data
  }

  session['revoke'] = True if form.get('revoke') else False
  session['pac_id'] = pac_id

  return json.dumps(message)


@api.route("/pac_status")
def pac_status():
  pac_id = session.get('pac_id')
  if pac_id is None:
    logging.error("pac_status request failed")
    message = {
        "status": "error"
    }
    return json.dumps(message)

  revoke = session.get('revoke')

  # print(revoke)

  data = {
      'id': pac_id
  }

  json_data = json.dumps(data).encode("utf-8")

  check_url = config['issuer']['url'] + "/check-offer"

  headers = {
      "Content-Type": "application/json",
      "Authorization": f"Bearer {config['issuer']['token']}"
  }

  # print(f'check_url: {check_url}')
  # print(headers)
  # print(json_data)

  req = urllib.request.Request(check_url, json_data, headers)

  with urllib.request.urlopen(req, context=context) as f:
      res = json.loads(f.read().decode())

  # print(res)

  status = res['status']

  if status == 'CREDENTIAL_ISSUED' and revoke:
      uuid = res['uuid']
      data = {
          "uuid": uuid,
          "state": 'revoke'
          # list: <optional URI of a specific statuslist for which to set/unset the status>
      }

      headers = {
          "Content-Type": "application/json",
          "Authorization": f"Bearer {config['issuer']['token']}"
      }

      json_data = json.dumps(data).encode("utf-8")

      revoke_url = config['issuer']['url'] + "/revoke-credential"

      req = urllib.request.Request(revoke_url, json_data, headers)
      with urllib.request.urlopen(req, context=context) as f:
          res = json.loads(f.read().decode())

  return json.dumps(status)


@api.route("/verifier")
def verifier():
  form = session.get('form')
  if form is None:
      logging.error("verifier request failed")
      message = {
          "status": "error"
      }
      return json.dumps(message)

  test_file = form.get('test_file')
  test_id = form.get('test_id')
  test = testset[test_file][test_id]

  name = test['type']

  data = {}
  json_data = json.dumps(data).encode("utf-8")

  create_url = config['verifier']['url'] + "/create-offer/" + name

  headers = {
      "Content-Type": "application/json",
      "Authorization": f"Bearer {config['verifier']['token']}"
  }

  # print(f'create_url: {create_url}')
  # print(headers)
  # print(json_data)

  req = urllib.request.Request(create_url, json_data, headers)
  with urllib.request.urlopen(req, context=context) as f:
    res = json.loads(f.read().decode())

  # print(res)

  qr_uri = res['requestUri']
  # check_uri = res['checkUri']
  state = res['state']

  message = {
      "status": "success",
      "test": test,
      "qr_uri": qr_uri,
      "state": state
  }

  # print(message)

  session['state'] = state

  return json.dumps(message)


@api.route("/verifier_status")
def verifier_status():
  state = session.get('state')
  if state is None:
      logging.error("verifier_status request failed")
      message = {
          "status": "error"
      }
      return json.dumps(message)

  check_url = config['verifier']['url'] + f'/check-offer/{state}'

  headers = {
      "Content-Type": "application/json",
      "Authorization": f"Bearer {config['verifier']['token']}"
  }

  req = urllib.request.Request(check_url, None, headers)
  with urllib.request.urlopen(req, context=context) as f:
      res = json.loads(f.read().decode())

  # print(res)

  status = res['status']
  result = res.get('result')

  message = {
      "status": status,
      "result": result
  }

  return json.dumps(message)


@api.route("/eduid")
def eduid():
  form = session.get('form')
  if form is None:
      logging.error("eduid request failed")
      message = {
          "status": "error"
      }
      return json.dumps(message)

  test_file = form.get('test_file')
  test_id = form.get('test_id')
  test = testset[test_file][test_id]

  credential_type = test['type']

  data = {
      'credentials': [credential_type],
      'grants': {
          'authorization_code': {
              'issuer_state': 'generate',
          },
      },
      'credentialDataSupplierInput': {},
  }

  tx_code_len = form.get('tx_code_len')
  if int(tx_code_len) > 0:
    tx_code_mode = form.get('tx_code_mode')
    tx_code = {
        'length': int(tx_code_len),
        'input_mode': tx_code_mode
    }
  else:
    tx_code = False

  data['grants']['authorization_code']['tx_code'] = tx_code

  json_data = json.dumps(data).encode("utf-8")

  create_url = config['eduid']['url'] + "/create-offer"

  headers = {
      "Content-Type": "application/json",
      "Authorization": f"Bearer {config['eduid']['token']}"
  }

  # print(f'create_url: {create_url}')
  # print(headers)
  # print(json_data)

  req = urllib.request.Request(create_url, json_data, headers)
  with urllib.request.urlopen(req, context=context) as f:
    res = json.loads(f.read().decode())

  qr_uri = res['uri']
  pin = res.get('txCode')
  state = res.get('id')

  message = {
      "status": "success",
      "test": test,
      "qr_uri": qr_uri,
      "pin": pin,
      "data": data
  }

  session['revoke'] = True if form.get('revoke') else False
  session['state'] = state

  return json.dumps(message)


@api.route("/eduid_status")
def eduid_status():
  state = session.get('state')
  if state is None:
    logging.error("pac_status request failed")
    message = {
        "status": "error"
    }
    return json.dumps(message)

  revoke = session.get('revoke')

  # print(revoke)

  data = {
      'id': state
  }

  json_data = json.dumps(data).encode("utf-8")

  check_url = config['eduid']['url'] + "/check-offer"

  headers = {
      "Content-Type": "application/json",
      "Authorization": f"Bearer {config['eduid']['token']}"
  }

  # print(f'check_url: {check_url}')
  # print(headers)
  # print(json_data)

  req = urllib.request.Request(check_url, json_data, headers)

  with urllib.request.urlopen(req, context=context) as f:
      res = json.loads(f.read().decode())

  # print(res)

  status = res['status']

  if status == 'CREDENTIAL_ISSUED' and revoke:
      uuid = res['uuid']
      data = {
          "uuid": uuid,
          "state": 'revoke'
          # list: <optional URI of a specific statuslist for which to set/unset the status>
      }

      headers = {
          "Content-Type": "application/json",
          "Authorization": f"Bearer {config['eduid']['token']}"
      }

      json_data = json.dumps(data).encode("utf-8")

      revoke_url = config['eduid']['url'] + "/revoke-credential"

      req = urllib.request.Request(revoke_url, json_data, headers)
      with urllib.request.urlopen(req, context=context) as f:
          res = json.loads(f.read().decode())

  return json.dumps(status)
