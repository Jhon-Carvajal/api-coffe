# Importación de librerías
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

# Inicialización de la aplicación Flask y configuración de CORS
app = Flask(__name__)
cors = CORS(app)
app.config["JWT_SECRET_KEY"] = "super-secret"
jwt = JWTManager(app)


# Ruta para crear un token JWT de acceso tras la validación del usuario
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


# Función para limpiar la URL, reemplazando parámetros dinámicos por "?"
def limpiarURL(url):
    partes = url.split("/")
    for laParte in partes:
        if re.search('\\d', laParte):
            url = url.replace(laParte, "?")
    return url


# Función para validar si el rol tiene permiso para acceder a la ruta
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


#### Rutas para gestionar usuarios y operaciones CRUD ####

# Ruta para obtener todos los usuarios
@app.route("/usuarios", methods=['GET'])
def getusuarios():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/usuarios'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


# Ruta para crear un nuevo usuario
@app.route("/usuario", methods=['POST'])
def crearusuario():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/usuario'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


# Ruta para obtener un usuario específico por ID
@app.route("/usuario/<string:id>", methods=['GET'])
def getusuario(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/usuario/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


# Ruta para modificar un usuario existente
@app.route("/usuario/<string:id>", methods=['PUT'])
def modificarusuario(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/usuario/' + id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


# Ruta para eliminar un usuario por ID
@app.route("/usuario/<string:id>", methods=['DELETE'])
def eliminarusuario(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/usuario/' + id
    response = requests.delete(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


#### Rutas para gestionar datos de sensores ####

# Ruta para obtener los datos de sensores
@app.route("/datosias", methods=['GET'])
def getdatosias():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/datosias'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


# Ruta para obtener un dato de sensor específico por ID
@app.route("/datosia/<string:id>", methods=['GET'])
def datosia(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/datosia/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


# Ruta para eliminar un dato de sensor por ID
@app.route("/datosia/<string:id>", methods=['DELETE'])
def eliminardatosia(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/datosia/' + id
    response = requests.delete(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

#### Rutas de Machine Learning y Chirpstack ####


# Ruta para generar una sugerencia basada en los datos de entrada
@app.route("/sugerenciam", methods=['POST'])
def generar_sugerencia():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/sugerenciam'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


# Ruta para guardar los valores de sensores recibidos
@app.route("/valores", methods=['POST'])
def guardar_datos():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-coffe"] + '/valores'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


# Ruta de prueba para verificar si el servidor está corriendo
@app.route("/", methods=['GET'])
def test():
    json = {}
    json["message"] = "Server running ..."
    return jsonify(json)


# Función para cargar el archivo de configuración
def loadFileConfig():
    with open('config.json') as f:
        data = json.load(f)
    return data


# Iniciar el servidor Flask
if __name__ == '__main__':
    dataConfig = loadFileConfig()
    print("Server running : " + "http://" + dataConfig["url-backend"] + ":" + str(dataConfig["port"]))
    serve(app, host=dataConfig["url-backend"], port=dataConfig["port"])