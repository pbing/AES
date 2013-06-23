#!/bin/bash

# Don't use salt in order to get no salted header in message.cpt
openssl enc -aes128 -in message.txt -out message.cpt -pass pass:mysecret -nosalt -p > keys.txt

