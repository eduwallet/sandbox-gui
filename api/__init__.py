#!/usr/bin/env python
import os
import json

testset = {}

for file in sorted(os.listdir('tests')):
  if file.endswith(".json"):
    with open('tests/' + file) as data:
      print(f"loading {file}")
      tests = json.load(data)

    for k, v in tests.items():
      credential = v.get('credential')
      if credential:
        with open(f'tests/credentials/{credential}') as data:
          print(f" - loading {credential}")
          cred = json.load(data)
          v['credential'] = cred

    name = file[:-5]
    testset[name] = tests

with open(os.getenv('CONF_PATH', '') + 'config.json') as data:
  print('loading config.json')
  config = json.load(data)
