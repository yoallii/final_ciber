import os
import requests
import urllib3
from base64 import b64encode
from flask import Flask, render_template, request, redirect, url_for, session
import random
from datetime import datetime
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load environment variables
load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", os.urandom(24).hex())

# Configuration from .env
BASE_HOST = os.getenv("BASE_HOST", "54.218.56.253")
PORT_MANAGER = int(os.getenv("PORT_MANAGER", "55000"))
PORT_INDEXER = int(os.getenv("PORT_INDEXER", "9200"))
USERNAME = os.getenv("USERNAME")
PASSWORD = os.getenv("PASSWORD")
INDEXER_USERNAME = os.getenv("indexer_username")
INDEXER_PASSWORD = os.getenv("indexer_password")

BASE_URL_MANAGER = f"https://{BASE_HOST}:{PORT_MANAGER}"
BASE_URL_INDEXER = f"https://{BASE_HOST}:{PORT_INDEXER}"

def get_token(username, password):
    try:
        login_url = f"{BASE_URL_MANAGER}/security/user/authenticate"
        auth = b64encode(f"{username}:{password}".encode()).decode()
        headers = {
            "Authorization": f"Basic {auth}",
            "Content-Type": "application/json"
        }
        response = requests.post(login_url, headers=headers, verify=False, timeout=10)
        response.raise_for_status()
        return response.json()["data"]["token"]
    except requests.RequestException:
        return None

def make_request(method, endpoint, token, params=None, data=None, port=PORT_MANAGER):
    base_url = BASE_URL_INDEXER if port == PORT_INDEXER else BASE_URL_MANAGER
    url = f"{base_url}{endpoint}"
    
    headers = {
        "Content-Type": "application/json"
    }
    
    if port == PORT_INDEXER:
        if not INDEXER_USERNAME or not INDEXER_PASSWORD:
            raise ValueError("Indexer credentials not provided")
        auth = b64encode(f"{INDEXER_USERNAME}:{INDEXER_PASSWORD}".encode()).decode()
        headers["Authorization"] = f"Basic {auth}"
    else:
        headers["Authorization"] = f"Bearer {token}"
    
    try:
        if method == "GET":
            response = requests.get(url, headers=headers, params=params, json=data, verify=False, timeout=10)
        elif method == "PUT":
            response = requests.put(url, headers=headers, params=params, json=data, verify=False, timeout=10)
        elif method == "DELETE":
            response = requests.delete(url, headers=headers, params=params, json=data, verify=False, timeout=10)
        else:
            raise ValueError(f"Unsupported method: {method}")
        
        response.raise_for_status()
        return response.json() if response.text else {"message": "Operation successful"}
    except requests.RequestException as e:
        raise Exception(f"Request failed: {str(e)}")

@app.route('/', methods=['GET', 'POST'])
def login():
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

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'token' not in session:
        return redirect(url_for('login'))
    
    token = session['token']
    results = {}
    active_section = None
    log_levels = ['INFO', 'WARNING', 'ERROR', 'CRITICAL']
    services = ['sshd', 'apache', 'nginx', 'mysql', 'system']
    actions = ['failed login', 'connection established', 'access denied', 'service started', 'authentication success']
    users = ['root', 'admin', 'user1', 'guest', 'test']
    ips = ['192.168.1.10', '10.0.0.5', '172.16.0.100', '8.8.8.8']
    
    if request.method == 'POST':
        action = request.form.get('action')
        active_section = action
        
        try:
            if action == 'vulnerabilities_by_severity':
                severity = request.form['severity']
                limit = int(request.form.get('limit', 10))
                query = {
                    "size": limit,
                    "query": {
                        "match": {
                            "vulnerability.severity": severity
                        }
                    }
                }
                data = make_request("GET", "/wazuh-states-vulnerabilities-ip-172-31-24-173/_search", 
                                  token, data=query, port=PORT_INDEXER)
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
            
            elif action == 'vulnerabilities_by_keyword':
                keyword = request.form['keyword']
                limit = int(request.form.get('limit', 10))
                query = {
                    "size": limit,
                    "query": {
                        "wildcard": {
                            "vulnerability.description": f"{keyword}"
                        }
                    }
                }
                data = make_request("GET", "/wazuh-states-vulnerabilities-ip-172-31-24-173/_search", 
                                  token, data=query, port=PORT_INDEXER)
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
            
            elif action == 'agent_action':
                agent_id = request.form['agent_id']
                operation = request.form['operation']
                if operation == "upgrade":
                    make_request("PUT", f"/agents/upgrade", token, params={"agents_list": agent_id}, port=PORT_MANAGER)
                    results[action] = {"message": f"Agente {agent_id} actualizado"}
                elif operation == "restart":
                    make_request("PUT", f"/agents/{agent_id}/restart", token, port=PORT_MANAGER)
                    results[action] = {"message": f"Agente {agent_id} reiniciado"}
                elif operation == "delete":
                    make_request("DELETE", f"/agents", token, params={"agents_list": agent_id}, port=PORT_MANAGER)
                    results[action] = {"message": f"Agente {agent_id} borrado"}
            
            elif action == 'common_vulnerability':
                cve = request.form['cve']
                query = {
                    "query": {
                        "match": {
                            "vulnerability.id": cve
                        }
                    }
                }
                data = make_request("GET", "/wazuh-states-vulnerabilities-ip-172-31-24-173/_search", 
                                  token, data=query, port=PORT_INDEXER)
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
            
            elif action == 'top10_vulnerabilities':
                query = {
                    "size": 10,
                    "sort": [{"vulnerability.score.base": {"order": "desc"}}]
                }
                data = make_request("GET", "/wazuh-states-vulnerabilities-ip-172-31-24-173/_search", 
                                  token, data=query, port=PORT_INDEXER)
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
            
            elif action == 'top10_agents':
                query = {
                    "size": 0,
                    "aggs": {
                        "by_agent": {
                            "terms": {
                                "field": "agent.id",
                                "size": 10,
                                "order": {"_count": "desc"}
                            },
                            "aggs": {
                                "agent_info": {
                                    "top_hits": {
                                        "size": 1,
                                        "_source": ["agent.id", "agent.name"]
                                    }
                                }
                            }
                        }
                    }
                }
                data = make_request("GET", "/wazuh-states-vulnerabilities-ip-172-31-24-173/_search", 
                                token, data=query, port=PORT_INDEXER)
                top_agents = [
                    {
                        "id": bucket["agent_info"]["hits"]["hits"][0]["_source"]["agent"]["id"],
                        "name": bucket["agent_info"]["hits"]["hits"][0]["_source"]["agent"]["name"],
                        "vulnerability_count": bucket["doc_count"]
                    }
                    for bucket in data["aggregations"]["by_agent"]["buckets"]
                ]
                results[action] = {
                    "title": "Top 10 Agentes con más vulnerabilidades",
                    "data": top_agents
                }
            elif action == 'server_status':
                status_type = request.form['status_type']
                try:
                    if status_type == "configuration":
                        data = make_request("GET", "/manager/configuration", token, port=PORT_MANAGER)
                        config_data = data.get("data", {}).get("affected_items", [{}])[0] if data.get("data") else {}

                        def simplify_config(config):
                            items = []
                            def process_item(key, value):
                                if isinstance(value, dict):
                                    for sub_key, sub_value in value.items():
                                        process_item(f"{key} {sub_key}", sub_value)
                                elif isinstance(value, list):
                                    if all(not isinstance(v, (dict, list)) for v in value):
                                        items.append((key, ", ".join(str(v) for v in value)))
                                    else:
                                        for i, item in enumerate(value):
                                            if isinstance(item, dict):
                                                for sub_key, sub_value in item.items():
                                                    process_item(f"{key} {i} {sub_key}", sub_value)
                                            else:
                                                items.append((f"{key} {i}", str(item)))
                                else:
                                    items.append((key, str(value)))
                            
                            for key, value in config.items():
                                process_item(key, value)
                            return items

                        formatted_config = simplify_config(config_data) if config_data else [("Estado", "No hay configuración disponible")]
                        results[action] = {
                            "title": "Configuración del servidor",
                            "data": formatted_config
                        }
                    elif status_type == "logs":
                        data = make_request("GET", "/manager/logs", token, port=PORT_MANAGER)
                        logs_data = data.get("data", {}).get("affected_items", [])[:5] if data.get("data") else []
                        results[action] = {
                            "title": "Últimos logs del servidor",
                            "data": logs_data if logs_data else [{"timestamp": "N/A", "level": "N/A", "message": "No hay logs disponibles"}]
                        }
                    elif status_type == "log_summary":
                        data = make_request("GET", "/manager/logs/summary", token, port=PORT_MANAGER)
                        summary_data = data.get("data", {}) if data.get("data") else {}
                        results[action] = {
                            "title": "Resumen de logs del servidor",
                            "data": summary_data if summary_data else {"message": "No hay resumen disponible"}
                        }
                    elif status_type == "groups":
                        data = make_request("GET", "/groups", token, port=PORT_MANAGER)
                        groups_data = data.get("data", {}).get("affected_items", []) if data.get("data") else []
                        results[action] = {
                            "title": "Grupos del servidor",
                            "data": groups_data if groups_data else [{"name": "N/A"}]
                        }
                    elif status_type == "tasks":
                        data = make_request("GET", "/tasks/status", token, port=PORT_MANAGER)
                        tasks_data = data.get("data", {}).get("affected_items", []) if data.get("data") else []
                        results[action] = {
                            "title": "Estado de las tareas",
                            "data": tasks_data if tasks_data else [{"task_id": "N/A", "status": "N/A"}]
                        }
                except Exception as e:
                    results[action] = {
                        "title": f"Error al obtener {status_type}",
                        "error": str(e)
                    }

            elif action == 'inventory':
                agent_id = request.form['agent_id']
                inv_type = request.form['inv_type']
                data = make_request("GET", f"/syscollector/{agent_id}/{inv_type}", token, port=PORT_MANAGER)
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
            elif action == 'generate_decoder_rule':
                syslog_input = request.form.get('syslog_input', '').strip()
                generated_log = None
                
                if 'generate_random' in request.form:
                    current_time = datetime.now().strftime("%b %d %H:%M:%S")
                    hostname = f"host{random.randint(1, 100)}"
                    log_level = random.choice(log_levels)
                    service = random.choice(services)
                    action = random.choice(actions)
                    user = random.choice(users)
                    ip = random.choice(ips)
                    
                    syslog_input = f"{current_time} {hostname} {service}[{random.randint(1000,9999)}]: {log_level} {action} for user {user} from {ip}"
                    generated_log = syslog_input

                if syslog_input:
                    parts = syslog_input.split()
                    timestamp = " ".join(parts[:3])
                    hostname = parts[3]
                    message = " ".join(parts[4:])

                    decoder_xml = f"""<decoder name="custom_syslog_{hostname}">
            <prematch>{timestamp} {hostname}</prematch>
        </decoder>
        <decoder name="custom_syslog_{hostname}_fields">
            <parent>custom_syslog_{hostname}</parent>
            <regex>{message.replace(' ', '\\s+')}</regex>
            <order>service, pid, level, action, user, source_ip</order>
        </decoder>"""

                    rule_xml = f"""<group name="custom_syslog_{hostname}">
            <rule id="100{random.randint(100,999)}" level="3">
                <decoded_as>custom_syslog_{hostname}</decoded_as>
                <description>Evento syslog personalizado: {message}</description>
                <mitre>
                    <id>T1078</id>
                </mitre>
            </rule>
        </group>"""

                    results['generate_decoder_rule'] = {
                        "title": "Resultados Generados",
                        "decoder": decoder_xml,
                        "rule": rule_xml,
                        "generated_log": generated_log if generated_log else None,
                        "original_log": syslog_input,
                        "message": "¡Log, decodificador y regla generados con éxito!"
                    }
                else:
                    results['generate_decoder_rule'] = {
                        "title": "Error",
                        "error": "Por favor, ingresa un log o genera uno aleatorio."
                    }
        
        except Exception as e:
            results[action] = {"error": str(e)}

    return render_template('dashboard.html', results=results, active_section=active_section)

@app.route('/logout')
def logout():
    session.pop('token', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)