import os
from flask import Flask
from flask import jsonify
from flask import request
from flask_cors import CORS
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
        return jsonify({"token": access_token, "user_id": user["_id"], "nombre": user["nombre"],
                        "apellidos": user["apellidos"],
                        "correo": user["correo"]})
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

###lote y variedad de cafe ###


@app.route("/lotes", methods=['GET'])
def getlotes():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/lotes'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/lote", methods=['POST'])
def crearlote():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/lote'
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


###cosecha del lote ###


@app.route("/cosechas", methods=['GET'])
def getcosechas():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/cosechas'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/cosecha", methods=['POST'])
def crearcosecha():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/cosecha'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/cosecha/<string:id>", methods=['GET'])
def getcosecha(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/cosecha/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/cosecha/<string:id>", methods=['PUT'])
def modificarcosecha(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/cosecha/' + id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/cosechae/<string:id>", methods=['DELETE'])
def eliminarcosecha(id):
    url = dataConfig["url-backend-coffe"] + '/cosechae/' + id
    response = requests.delete(url)
    json = response.json()
    return jsonify(json)

##Nutrición


@app.route("/nutriciones", methods=['GET'])
def getnutriciones():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/nutriciones'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/nutricion", methods=['POST'])
def crearnutricion():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/nutricion'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/nutricion/<string:id>", methods=['GET'])
def getnutricion(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/nutricion/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/nutricion/<string:id>", methods=['PUT'])
def modificarnutricion(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/nutricion/' + id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/nutricion/<string:id>", methods=['DELETE'])
def eliminarnutricion(id):
    url = dataConfig["url-backend-coffe"] + '/nutricion/' + id
    response = requests.delete(url)
    json = response.json()
    return jsonify(json)


##fumigacion
@app.route("/fumigaciones", methods=['GET'])
def getfumigaciones():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/fumigaciones'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/fumigacion", methods=['POST'])
def crearfumigacion():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/fumigacion'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/fumigacion/<string:id>", methods=['GET'])
def getfumigacion(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/fumigacion/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/fumigacion/<string:id>", methods=['PUT'])
def modificarfumigacion(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/fumigacion/' + id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/fumigacion/<string:id>", methods=['DELETE'])
def eliminarfumigacion(id):
    url = dataConfig["url-backend-coffe"] + '/fumigacion/' + id
    response = requests.delete(url)
    json = response.json()
    return jsonify(json)


#DATOS SENSORES


@app.route("/datosias", methods=['GET'])
def getdatosias():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/datosias'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/datosia/<string:id>", methods=['GET'])
def datosia(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/datosia/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/datosia/<string:id>", methods=['DELETE'])
def eliminardatosia(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/datosia/' + id
    response = requests.delete(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/sugerencia", methods=['POST'])
def generar_sugerencial():
    # Recibir los datos como texto plano (cadena de números separados por comas)
    data = request.data.decode('utf-8')  # Ejemplo: "16.67,3.59,161.46"

    # Convertir la cadena en valores separados
    try:
        fosforo, nitrogeno, potasio = map(float, data.split(','))
    except ValueError:
        return jsonify({"error": "Se requieren tres valores numéricos separados por comas."}), 400

    # Crear un diccionario para enviarlo al backend interno
    datos = {
        "fosforo": fosforo,
        "nitrogeno": nitrogeno,
        "potasio": potasio
    }

    # Hacer la solicitud al backend interno con estos datos en formato JSON
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/sugerencia'

    # Enviar los datos como JSON al backend interno
    response = requests.post(url, headers=headers, json=datos)

    # Devolver la respuesta
    json_response = response.json()
    return jsonify(json_response)


##ML
@app.route("/sugerenciam", methods=['POST'])
def generar_sugerencia():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/sugerenciam'
    response = requests.post(url, headers=headers, json=data)
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