from flask import Flask, render_template, request, jsonify
app = Flask(__name__)

from pymongo import MongoClient
client = MongoClient('localhost', 27017)
db = client.timeattack

import hashlib, jwt, datetime


@app.route('/')
def home():
  return render_template('login.html')


@app.route('/login', methods =['POST'])
def login():
    uid = request.form['uid']
    pwd = request.form['pwd']
    if uid == 'test@a.com' and pwd == '1234':
        return render_template('write.html')



@app.route("/join", methods=["POST"])
def join():
    uid_receive = request.form['uid_give']
    pwd_receive = request.form['pwd_give']

    hashed_uid = hashlib.sha256(uid_receive.encode('utf-8')).hexdigest()

    SECRET_KEY = 'test@a.com'

    payload = {'id': 'kihyeon',  # payload(내용물) 에 암호화를 원하는 정보를 담음
               'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=1800)}  # 만료 기한
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')  # 토큰 생성

    print(token)  # 토큰 출력

    decoded_token = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])  # 토큰과 해독키값을 알고있으면 디코딩가능
    print(decoded_token)  # {'id': 'kihyeon', 'exp': 1651586494} 정보와 만료 기한이 출력

    doc = {
        'uid': hashed_uid,
        'pwd': hashed_pwd,
    }

    db.timeattack.insert_one(doc)

    return jsonify({'response':'success', 'msg':'환영합니다!'})

if __name__ == '__main__':
   app.run('0.0.0.0', port=5000, debug=True)