import os
from flask import Flask
from flask import jsonify
from flask import request
from flask_cors import CORS
##from keras.models import load_model
import json
from waitress import serve
import datetime
import requests
import re
from flask_jwt_extended import create_access_token, verify_jwt_in_request
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

app = Flask(__name__)
cors = CORS(app)
app.config["JWT_SECRET_KEY"] = "super-secret"
jwt = JWTManager(app)


@app.route("/login", methods=["POST"])
def create_token():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/usuarios/validar'
    response = requests.post(url, json=data, headers=headers)
    if response.status_code == 200:
        user = response.json()
        expires = datetime.timedelta(seconds=60 * 60 * 24)
        access_token = create_access_token(identity=user, expires_delta=expires)
        return jsonify({"token": access_token, "user_id": user["_id"]})
    else:
        return jsonify({"invalido": "usuario o contraseña incorrecto"}), 401


# Funcion que se ejecutará primero antes de la consulta solicitada
@app.before_request
def before_request_callback():
    endPoint = limpiarURL(request.path)
    excludedRoutes = ["/login"]
    if excludedRoutes.__contains__(request.path):
        pass
    elif verify_jwt_in_request():
        usuario = get_jwt_identity()
        if usuario["rol"] is not None:
            tienePersmiso = validarPermiso(endPoint, request.method, usuario["rol"]["_id"])
            if not tienePersmiso:
                return jsonify({"Acceso": "Permission denied"}), 401
        else:
            return jsonify({"Acceso": "Permission denied"}), 401


def limpiarURL(url):
    partes = url.split("/")
    for laParte in partes:
        if re.search('\\d', laParte):
            url = url.replace(laParte, "?")
    return url


def validarPermiso(endPoint, metodo, idRol):
    url = dataConfig["url-backend-security"] + "/permisos-roles/validar-permiso/rol/" + str(idRol)
    tienePermiso = False
    headers = {"Content-Type": "application/json; charset=utf-8"}
    body = {
        "url": endPoint,
        "metodo": metodo
    }
    response = requests.get(url, json=body, headers=headers)
    try:
        data = response.json()
        if ("_id" in data):
           tienePermiso = True
    except:
        pass
    return tienePermiso


####Redireccionamiento###
@app.route("/usuarios", methods=['GET'])
def getusuarios():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/usuarios'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/usuario", methods=['POST'])
def crearusuario():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/usuario'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/usuario/<string:id>", methods=['GET'])
def getusuario(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/usuario/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/usuario/<string:id>", methods=['PUT'])
def modificarusuario(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/usuario/' + id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/usuario/<string:id>", methods=['DELETE'])
def eliminarusuario(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/usuario/' + id
    response = requests.delete(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

##redireccionamiento a finca


@app.route("/fincas", methods=['GET'])
def getfincas():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/fincas'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/finca", methods=['POST'])
def crearfinca():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/finca'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/finca/<string:id>", methods=['GET'])
def getfinca(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/finca/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/finca/<string:id>", methods=['PUT'])
def modificarfinca(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/finca/' + id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/finca/<string:id>", methods=['DELETE'])
def eliminarfinca(id):
    url = dataConfig["url-backend-coffe"] + '/finca/' + id
    response = requests.delete(url)
    json = response.json()
    return jsonify(json)

###lote###


@app.route("/lotes", methods=['GET'])
def getlotes():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/lotes'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/lote/", methods=['POST'])
def crearlote():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/lote/'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/lote/<string:id>", methods=['GET'])
def getlote(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/lote/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/lote/<string:id>", methods=['PUT'])
def modificarlote(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/lote/' + id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/lote/<string:id>", methods=['DELETE'])
def eliminarlote(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/lote/' + id
    response = requests.delete(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

###cafe###


@app.route("/cafes", methods=['GET'])
def getcafes():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/cafes'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/cafe/", methods=['POST'])
def crearcafe():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/cafe/'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/cafe/<string:id>", methods=['GET'])
def getcafe(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/cafe/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/cafe/<string:id>", methods=['PUT'])
def modificarcafe(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/cafe/' + id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/cafe/<string:id>", methods=['DELETE'])
def eliminarcafe(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/cafe/' + id
    response = requests.delete(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

###imagen###


@app.route("/imagenes", methods=['GET'])
def imagenes():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/imagenes'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/crearimagen/", methods=['POST'])
def crearimagen():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/crearimagen/'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/modificarimagen/<string:id>", methods=['PUT'])
def modificarimagen(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/modificarimagen/' + id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/imagen/<string:id>", methods=['GET'])
def imagen(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/imagen/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/", methods=['GET'])
def test():
    json = {}
    json["message"] = "Server running ..."
    return jsonify(json)


def loadFileConfig():
    with open('config.json') as f:
        data = json.load(f)
    return data


if __name__ == '__main__':
    dataConfig = loadFileConfig()
    print("Server running : " + "http://" + dataConfig["url-backend"] + ":" + str(dataConfig["port"]))
    serve(app, host=dataConfig["url-backend"], port=dataConfig["port"])