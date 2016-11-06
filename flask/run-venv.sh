#!/usr/bin/env bash
# Copyright (c) 2016 grantedby.me
# Author: GrantedByMe <info@grantedby.me>
python3 -m virtualenv env
. env/bin/activate
env/bin/pip3 install -r requirements.txt -U
