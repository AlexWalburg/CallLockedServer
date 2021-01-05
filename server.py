from flask import Flask, jsonify, request
import sqlite3
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64
import traceback
import time
import json

db = "phones.db"
app = Flask("CallLock")

@app.route('/')
def default_connection():
    return "server is up"

@app.route('/makeListing',methods=['post'])
def create_listing():
    with sqlite3.connect(db) as con:
        c = con.cursor()
        try:
            key = request.form['key']
            delKey = request.form['delKey']
            pubkey = request.form['pubkey']
            if(key==''):
                print("setting to null!")
                key = None
            name = request.form['name']
            t = (delKey,name,key, pubkey)
            c.execute('INSERT INTO listings (deleteKey,name,privkey,pubkey) VALUES (?,?,?,?)', t)
            new_listing_id = c.lastrowid
            con.commit()
            return jsonify(new_listing_id)
        except Exception as e:
            print(e)
            con.rollback()
            return jsonify("error")

@app.route('/searchPublicListings',methods=['post'])
def search_public_listings():
    with sqlite3.connect(db) as con:
        c = con.cursor()
        try:
            searchText = request.form['searchText']
            a = c.execute("SELECT listing, name, pubkey FROM listings WHERE pubkey <> '' AND name LIKE '%' || ? || '%'",(searchText,)).fetchall()
            return jsonify(a)
        except Exception as e:
            print(e)
            return jsonify("error")

@app.route('/publicizeListing', methods=['post'])
def publicize_listing():
    with sqlite3.connect(db) as con:
        c = con.cursor()
        try:
            listingId = request.form['listingId']
            encryptedListingId = base64.b64decode(request.form['encryptedListingId'])
            privkey = request.form['privKey']
            delKey = c.execute("SELECT deleteKey FROM listings WHERE ?=listing", (listingId,)).fetchone()
            delKey = delKey[0]
            key = serialization.load_pem_private_key(delKey.encode('utf-8'), password=None)
            unencryptedListingId = key.decrypt(encryptedListingId, padding.OAEP(algorithm=None,mgf=None,label=None))
            print(str(unencryptedListingId) + ":" + str(listingId))
            print(type(listingId))
            if(unencryptedListingId==int(listingId)):
                c.execute("UPDATE listings SET privkey=? WHERE LISTING=?", (privkey,listingId))
                con.commit()
                return jsonify("success")
            return jsonify("encryption failed")
        except Exception as e:
            traceback.print_exc()
            con.rollback()
            return jsonify("failure")


@app.route('/addNumber', methods=['post'])
def add_number():
    with sqlite3.connect(db) as con:
        c = con.cursor()
        try:
            listingId = int(request.form['listingId'])
            encryptedPhoneNumber = request.form['encryptedPhoneNumber']
            encryptedName = request.form['encryptedName']
            timestamp = int(time.time()*1000);
            insertRow = (listingId,encryptedPhoneNumber,timestamp,encryptedName)
            c.execute("INSERT INTO users VALUES (?,?,?,?)", insertRow)
            con.commit()
            return jsonify("success")
        except Exception as e:
            print(e)
            return jsonify("failure")

@app.route('/getListing',methods=['post'])
def get_listing():
    with sqlite3.connect(db) as con:
        c = con.cursor()
        try:
            listingId = request.form['listingId']
            results = c.execute("SELECT encryptedNum, name FROM users WHERE ? = listing", listingId).fetchall()
            return jsonify(results)
        except:
            return jsonify("error")

@app.route('/getListingName',methods=['post'])
def get_listing_name():
    with sqlite3.connect(db) as con:
        c = con.cursor()
        try:
            listingId = int(request.form['listingId'])
            result = c.execute("SELECT name FROM listings WHERE ? = listing", (listingId,)).fetchone()
            return jsonify(result)
        except Exception as e:
            throw(e)
            return jsonify("error")

@app.route('/getListingAfterTime',methods=['post'])
def get_listing_after_time():
    with sqlite3.connect(db) as con:
        c = con.cursor()
        try:
            listingId = request.form['listingId']
            timestamp = request.form['timestamp']
            results = c.execute("SELECT encryptedNum, name FROM users WHERE ? = listing and ? < timestamp", (listingId, timestamp)).fetchall()
            return jsonify(results)
        except Exception as e:
            print(e)
            return jsonify("error")

@app.route('/batchGetListingAfterTime', methods=['post'])
def batch_get_listing_after_time():
    with sqlite3.connect(db) as con:
        c = con.cursor()
        try:
            updates = json.JSONDecoder().decode(request.form['updates'])
            results = {}
            for listingId, timestamp in updates.items():
                results[listingId] = c.execute("SELECT encryptedNum, name FROM users WHERE ? = listing and ? < timestamp", (listingId, timestamp)).fetchall()
            return jsonify(results)
        except Exception as e:
            print(e)
            return jsonify("error")

@app.route('/deleteNumber',methods=['post'])
def delete_number():
    with sqlite3.connect(db) as con:
        c=con.cursor()
        try:
            listingId = request.form['listingId']
            encryptedDelPhrase = base64.b64decode(request.form['encryptedDelPhrase'])
            delKey = c.execute("SELECT deleteKey FROM listings WHERE ?=listing", listingId).fetchone()
            delKey = delKey[0]
            key = RSA.importKey(delKey)
            cipher = PKCS1_v1_5.new(key)
            delPhrase = cipher.decrypt(encryptedDelPhrase)
            delPhrase = delPhrase.strip() #base64 encodes don't have whitespace, this was an error we need to fix
            delPhrase=str(delPhrase,'utf-8')
            searchTerms = {"listingId" : listingId, "delPhrase" : delPhrase}
            print(searchTerms["delPhrase"])
            c.execute("delete FROM users WHERE listing=:listingId AND encryptedNum like :delPhrase", searchTerms)
            con.commit()
            return jsonify("success")
        except Exception as e:
            print(e)
            con.rollback()
            return jsonify("failure")


if __name__ == '__main__':
    app.run(host='0.0.0.0')
