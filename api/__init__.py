#!/usr/bin/env python
import os
import json

testset = {}

for file in os.listdir('tests'):
    if file.endswith(".json"):
        with open('tests/' + file) as data:
            tests = json.load(data)

        for k, v in tests.items():
            credential = v['credential']
            with open(f'tests/credentials/{credential}') as data:
                cred = json.load(data)
                v['credential'] = cred

        name = file[:-5]
        testset[name] = tests

with open(os.getenv('CONF_PATH', '') + 'config.json') as data:
    config = json.load(data)
