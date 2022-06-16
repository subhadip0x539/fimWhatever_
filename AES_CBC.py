import pyminizip
import os
from Crypto.Cipher import AES
import hashlib
import time


def padding(file):
    while len(file)%16 != 0:
        file = file + b'0'        
    return file

def zip(id, enc, db, db_bak, anal, ks):
    secret_password = ks.objects().only('MASTER_KEY').first().MASTER_KEY.encode()
    key = hashlib.sha256(secret_password).digest()
    mode = AES.MODE_CBC
    IV = ks.objects().only('IV').first().IV.encode()
    cipher = AES.new(key, mode, IV)
    file = db.objects(id=id).only('file').first().file

    if enc == "Encrypt":
        output_zip = "./.secret/{}_{}.zip".format(file.split("/")[-1].split(".")[0], time.time())
        if not os.path.exists(".secret"):
            os.mkdir(".secret")
        pyminizip.compress(file, None, output_zip, id, 5)

        with open(file, 'rb') as f:
            data = f.read()
    
        padded_data = padding(data)
        encrypted_data = cipher.encrypt(padded_data)
        with open(file, 'wb') as f:
            f.write(encrypted_data)

        db_bak.objects(file_id=id).update_one(inc__status=5)
        anal.objects().update_one(set__encs=len(db_bak.objects(status__gt=4)))
        os.system("echo {} | sudo -S chown root {}".format(os.environ.get("SUDO_PASSWD"), file))
        return "Encryption complete"    
    
    if enc == "Decrypt":
        with open(file, 'rb') as f:
            data = f.read()
        os.system("echo {} | sudo -S chown {} {}".format(os.environ.get("SUDO_PASSWD"), os.environ.get("USER"), file))

        decrypted_data = cipher.decrypt(data)
        with open(file, 'wb') as f:
            f.write(decrypted_data.rstrip(b'0'))

        db_bak.objects(file_id=id).update_one(dec__status=5)
        anal.objects().update_one(set__encs=len(db_bak.objects(status__gt=4)))

        return "Decryption complete"