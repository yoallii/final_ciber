import os
import requests
import urllib3
from base64 import b64encode
from flask import Flask, render_template, request, redirect, url_for, session
from dotenv import load_dotenv

# Python + Flask -> HTML + CSS <-> API Wazuh
'''La aplicación usa puertos para comunicarse con estos dos servicios y un token para autenticación
# Servicio de gestión = agentes... dispositivos 55000
# Servicio de indexación = datos... vulnerabilidades/logs 9200
'''

# Ignora advertencias de SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Carga las variables de entorno desde el archivo .env
load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", os.urandom(24).hex())

# Configuración del servidor
BASE_HOST = os.getenv("BASE_HOST", "54.218.56.253")
PORT_MANAGER = int(os.getenv("PORT_MANAGER", "55000"))  # Puerto para agentes
PORT_INDEXER = int(os.getenv("PORT_INDEXER", "9200"))   # Puerto para indexador
USERNAME = os.getenv("USERNAME")
PASSWORD = os.getenv("PASSWORD")
INDEXER_USERNAME = os.getenv("INDEXER_USERNAME")
INDEXER_PASSWORD = os.getenv("INDEXER_PASSWORD")

# URLs para las peticiones
BASE_URL_MANAGER = f"https://{BASE_HOST}:{PORT_MANAGER}"  # Interactúa con el gestor... agentes
BASE_URL_INDEXER = f"https://{BASE_HOST}:{PORT_INDEXER}"  # Búsqueda de datos indexados... vulnerabilidades/logs

# Obtiene el token para peticiones 
def get_token(username, password):
    login_url = f"{BASE_URL_MANAGER}/security/user/authenticate"
    auth = b64encode(f"{username}:{password}".encode()).decode()
    headers = {"Authorization": f"Basic {auth}", "Content-Type": "application/json"}
    try:
        response = requests.post(login_url, headers=headers, verify=False, timeout=10)
        response.raise_for_status()
        return response.json()["data"]["token"]
    except requests.RequestException:
        return None

# Envía peticiones al servidor
def make_request(method, endpoint, token, params=None, data=None, port=PORT_MANAGER):
    # Elige la URL correcta basada en el puerto
    base_url = BASE_URL_INDEXER if port == PORT_INDEXER else BASE_URL_MANAGER
    url = f"{base_url}{endpoint}"
    headers = {"Content-Type": "application/json"}
    if port == PORT_INDEXER:
        # Puerto del indexador 9200
        basic_auth = b64encode(f"{INDEXER_USERNAME}:{INDEXER_PASSWORD}".encode()).decode()
        headers["Authorization"] = f"Basic {basic_auth}"
    else:
        # Puerto del gestor 55000
        headers["Authorization"] = f"Bearer {token}"
    
    # Realiza las peticiones
    try:
        if method == "GET":
            respuesta = requests.get(url, headers=headers, params=params, json=data, verify=False, timeout=10)
        elif method == "PUT":
            respuesta = requests.put(url, headers=headers, params=params, json=data, verify=False, timeout=10)
        elif method == "DELETE":
            respuesta = requests.delete(url, headers=headers, params=params, json=data, verify=False, timeout=10)
        else:
            raise ValueError(f"Fallo en el método: {method}")
        respuesta.raise_for_status()
        return respuesta.json() if respuesta.text else {"message": "Operación exitosa"}
    except requests.RequestException as e:
        raise Exception(f"Fallo en la petición: {str(e)}")

# Página de inicio de sesión
@app.route('/', methods=['GET', 'POST'])
def login():
    """Página para inicio de sesión.
    
    Muestra la página de inicio de sesión
    
    """
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        token = get_token(username, password)   
        if token:
            session['token'] = token
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error="Usuario o contraseña incorrectos") 
    return render_template('login.html')

# Menú principal
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    # Confirma que el usuario está loggeado
    if 'token' not in session:
        return redirect(url_for('login'))  

    token = session['token']
    results = {}  
    active_section = None
    
    if request.method == 'POST':
        action = request.form.get('action')
        active_section = action    
        try:
            # ------------Vulnerabilidades por severidad-----------#
            if action == 'vulnerabilidades_por_severidad': 
                severity = request.form['severity']
                limit = int(request.form.get('limit', 10))
                query = {
                    "size": limit,
                    "query": {"match": {"vulnerability.severity": severity}}
                }
                data = make_request("GET", "/wazuh-states-vulnerabilities-ip-172-31-24-173/_search", token, data=query, port=PORT_INDEXER)
                vulnerabilities = [
                    {
                        "agent_id": hit["_source"]["agent"]["id"],
                        "title": hit["_source"]["vulnerability"]["description"],
                        "cve": hit["_source"]["vulnerability"]["id"],
                        "severity": hit["_source"]["vulnerability"]["severity"],
                        "timestamp": hit["_source"]["vulnerability"]["detected_at"]
                    } for hit in data["hits"]["hits"]
                ]
                results[action] = {
                    "title": f"Vulnerabilidades de severidad {severity} (mostrando {len(vulnerabilities)} de {data['hits']['total']['value']})",
                    "data": vulnerabilities
                }
            
            # ------------Vulnerabilidades por palabra-----------#
            elif action == 'vulnerabilidades_por_palabra':
                keyword = request.form['keyword']
                limit = int(request.form.get('limit', 10))
                query = {
                    "size": limit,
                    "query": {"wildcard": {"vulnerability.description": f"*{keyword.lower()}*"}}
                }
                data = make_request("GET", "/wazuh-states-vulnerabilities-ip-172-31-24-173/_search", token, data=query, port=PORT_INDEXER)
                vulnerabilities = [
                    {
                        "agent_id": hit["_source"]["agent"]["id"],
                        "title": hit["_source"]["vulnerability"]["description"],
                        "cve": hit["_source"]["vulnerability"]["id"],
                        "severity": hit["_source"]["vulnerability"]["severity"],
                        "timestamp": hit["_source"]["vulnerability"]["detected_at"]
                    } for hit in data["hits"]["hits"]
                ]
                results[action] = {
                    "title": f"Vulnerabilidades con '{keyword}' (mostrando {len(vulnerabilities)} de {data['hits']['total']['value']})",
                    "data": vulnerabilities
                }

            # ------------Acciones de agente: actualizar, reiniciar, eliminar-----------#
            elif action == 'accion_agente':
                agent_id = request.form['agent_id']
                operation = request.form['operation']
                if operation == "upgrade":
                    make_request("PUT", f"/agents/upgrade", token, params={"agents_list": agent_id})
                    results[action] = {"message": f"Agente {agent_id} actualizado"}
                elif operation == "restart":
                    make_request("PUT", f"/agents/{agent_id}/restart", token)
                    results[action] = {"message": f"Agente {agent_id} reiniciado"}
                elif operation == "delete":
                    make_request("DELETE", f"/agents", token, params={"agents_list": agent_id})
                    results[action] = {"message": f"Agente {agent_id} borrado"}
            
            # ------------Vulnerabilidades en común-----------#
            elif action == 'vulnerabilidad_comun':
                cve = request.form['cve']
                query = {
                    "query": {"match": {"vulnerability.id": cve}}
                }
                data = make_request("GET", "/wazuh-states-vulnerabilities-ip-172-31-24-173/_search", token, data=query, port=PORT_INDEXER)
                vulnerabilities = [
                    {
                        "agent_id": hit["_source"]["agent"]["id"],
                        "title": hit["_source"]["vulnerability"]["description"],
                        "cve": hit["_source"]["vulnerability"]["id"],
                        "severity": hit["_source"]["vulnerability"]["severity"],
                        "timestamp": hit["_source"]["vulnerability"]["detected_at"]
                    } for hit in data["hits"]["hits"]
                ]
                results[action] = {
                    "title": f"Equipos con {cve}",
                    "data": vulnerabilities
                }
            
            # ------------Top 10 vulnerabilidades-----------#
            elif action == 'top10_vulnerabilidades':
                query = {
                    "size": 10,
                    "sort": [{"vulnerability.score.base": {"order": "desc"}}]
                }
                data = make_request("GET", "/wazuh-states-vulnerabilities-ip-172-31-24-173/_search", token, data=query, port=PORT_INDEXER)
                vulnerabilities = [
                    {
                        "agent_id": hit["_source"]["agent"]["id"],
                        "title": hit["_source"]["vulnerability"]["description"],
                        "cve": hit["_source"]["vulnerability"]["id"],
                        "severity": hit["_source"]["vulnerability"]["severity"],
                        "timestamp": hit["_source"]["vulnerability"]["detected_at"]
                    } for hit in data["hits"]["hits"]
                ]
                results[action] = {
                    "title": "Top 10 Vulnerabilidades",
                    "data": vulnerabilities
                }
            
            # ------------Top 10 agentes-----------#
            elif action == 'top10_agentes':
                query = {
                    "size": 0,
                    "aggs": {
                        "by_agent": {
                            "terms": {"field": "agent.id", "size": 10, "order": {"_count": "desc"}},
                            "aggs": {
                                "agent_info": {"top_hits": {"size": 1, "_source": ["agent.id", "agent.name"]}}
                            }
                        }
                    }
                }
                data = make_request("GET", "/wazuh-states-vulnerabilities-ip-172-31-24-173/_search", token, data=query, port=PORT_INDEXER)
                top_agents = [
                    {
                        "id": bucket["agent_info"]["hits"]["hits"][0]["_source"]["agent"]["id"],
                        "name": bucket["agent_info"]["hits"]["hits"][0]["_source"]["agent"]["name"],
                        "vulnerability_count": bucket["doc_count"]
                    } for bucket in data["aggregations"]["by_agent"]["buckets"]
                ]
                results[action] = {
                    "title": "Top 10 Agentes con más vulnerabilidades",
                    "data": top_agents
                }
            
            # ------------Estado del servidor-----------#
            elif action == 'estado_servidor':
                status_type = request.form['status_type']
                try:
                    if status_type == "configuration":
                        data = make_request("GET", "/manager/configuration", token)
                        config_data = data.get("data", {}).get("affected_items", [{}])[0]
                        
                        def simplify_config(config):
                            """Convierte la configuración del servidor en una lista de pares clave-valor más legible."""
                            resultado = []
                            
                            # Si no hay configuración, devolvemos un mensaje por defecto
                            if not config:
                                return [("Estado", "No hay configuración disponible")]

                            # Recorremos cada clave y valor en el diccionario
                            for clave, valor in config.items():
                                if isinstance(valor, dict):
                                    # Si el valor es un diccionario, lo aplanamos combinando claves
                                    for subclave, subvalor in valor.items():
                                        resultado.append((f"{clave} {subclave}", str(subvalor)))
                                elif isinstance(valor, list):
                                    # Si el valor es una lista, la convertimos en una cadena separada por comas
                                    valores = [str(item) for item in valor]
                                    resultado.append((clave, ", ".join(valores)))
                                else:
                                    # Si es un valor simple (string, número, etc.), lo añadimos directamente
                                    resultado.append((clave, str(valor)))
                            
                            return resultado
                        
                        formatted_config = simplify_config(config_data)
                        results[action] = {"title": "Configuración del servidor", "data": formatted_config}
                    
                    elif status_type == "logs":
                        data = make_request("GET", "/manager/logs", token)
                        logs_data = data.get("data", {}).get("affected_items", [])[:5] or [{"timestamp": "N/A", "level": "N/A", "message": "No hay logs disponibles"}]
                        results[action] = {"title": "Últimos logs del servidor", "data": logs_data}
                    
                    elif status_type == "log_summary":
                        data = make_request("GET", "/manager/logs/summary", token)
                        summary_data = data.get("data", {}) or {"message": "No hay resumen disponible"}
                        results[action] = {"title": "Resumen de logs del servidor", "data": summary_data}
                    
                    elif status_type == "groups":
                        data = make_request("GET", "/groups", token)
                        groups_data = data.get("data", {}).get("affected_items", []) or [{"name": "N/A"}]
                        results[action] = {"title": "Grupos del servidor", "data": groups_data}
                    
                    elif status_type == "tasks":
                        data = make_request("GET", "/tasks/status", token)
                        tasks_data = data.get("data", {}).get("affected_items", []) or [{"task_id": "N/A", "status": "N/A"}]
                        results[action] = {"title": "Estado de las tareas", "data": tasks_data}
                
                except Exception as e:
                    results[action] = {"title": f"Error al obtener {status_type}", "error": str(e)}
            
            # ------------Inventario-----------#
            elif action == 'inventario_agente':
                agent_id = request.form['agent_id']
                inv_type = request.form['inv_type']
                data = make_request("GET", f"/syscollector/{agent_id}/{inv_type}", token)
                inventory_data = data["data"]["affected_items"]
                processed_data = []
                
                if inv_type == "hardware":
                    for item in inventory_data:
                        processed_data.append({
                            "board_serial": item.get("board_serial", "N/A"),
                            "cpu_name": item.get("cpu", {}).get("name", "N/A"),
                            "ram_total": item.get("ram", {}).get("total", "N/A")
                        })
                elif inv_type == "os":
                    for item in inventory_data:
                        processed_data.append({
                            "os_name": item.get("os", {}).get("name", "N/A"),
                            "os_version": item.get("os", {}).get("version", "N/A"),
                            "architecture": item.get("os", {}).get("architecture", "N/A")
                        })
                elif inv_type == "packages":
                    for item in inventory_data:
                        processed_data.append({
                            "name": item.get("name", "N/A"),
                            "version": item.get("version", "N/A"),
                            "description": item.get("description", "N/A")
                        })
                elif inv_type == "ports":
                    for item in inventory_data:
                        processed_data.append({
                            "local_ip": item.get("local", {}).get("ip", "N/A"),
                            "local_port": item.get("local", {}).get("port", "N/A"),
                            "protocol": item.get("protocol", "N/A")
                        })
                elif inv_type == "processes":
                    for item in inventory_data:
                        processed_data.append({
                            "pid": item.get("pid", "N/A"),
                            "name": item.get("name", "N/A"),
                            "state": item.get("state", "N/A")
                        })
                
                results[action] = {
                    "title": f"Inventario {inv_type} del agente {agent_id}",
                    "data": processed_data,
                    "inv_type": inv_type
                }
        
        except Exception as e:
            results[action] = {"error": str(e)}
    
    return render_template('dashboard.html', results=results, active_section=active_section)

# Cerrar sesión
@app.route('/logout')
def logout():
    """Cierra la sesión del usuario eliminando el token de la sesión."""
    session.pop('token', None)
    return redirect(url_for('login'))

# Ejecuta la aplicación
if __name__ == '__main__':
    port = int(os.getenv("PORT", 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
