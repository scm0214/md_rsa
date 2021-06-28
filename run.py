# python3.6
from flask import Flask,request,jsonify
from Md_Rsa import rsa_sign
app = Flask(__name__)

@app.route("/create/sign",methods=["POST"])
def create():
    data = request.get_json()
    print(data)
    data = data["data1"]
    print(data,type(data))
    time = str(data).split("|")[1]
    print ("time",time)
    data1 = {}
    
    result =str(rsa_sign(data))[2:-1]
    print((rsa_sign(data)))
    datajson = data 
    
    data1["sign"] = result
    data1["datajson"] = datajson.split("|")[0]
    data1["time"] = time
    # print(data1)
    return jsonify({
        "status":0,
        "message":"success",
        "data":data1
    })

app.run(debug=True,host="0.0.0",)