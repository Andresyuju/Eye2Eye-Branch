import whois
import socket
import requests
import builtwith
import ssl
import json
import csv

# Claves API para los servicios de Hackertarget y VirusTotal.
API_KEY = ''
API_KEY_VIRUSTOTAL = ''

# Función para obtener resultados de diferentes herramientas online.
def obtener_resultados_herramienta(herramienta, parametro):
    # Construcción de la URL para la solicitud API.
    url = f"https://api.hackertarget.com/{herramienta}/?q={parametro}&apikey={API_KEY}"
    # Realiza la solicitud HTTP GET.
    respuesta = requests.get(url)
    # Verifica el código de estado de la respuesta.
    if respuesta.status_code == 200:
        return respuesta.text
    else:
        return f"Error al obtener información. Código de estado: {respuesta.status_code}"

# Función para obtener información de dominio usando la API de Hackertarget.
def obtener_informacion_dominio(dominio):
    url = f"https://api.hackertarget.com/reverseiplookup/?q={dominio}&apikey={API_KEY}"
    respuesta = requests.get(url)
    if respuesta.status_code == 200:
        return respuesta.text
    else:
        return f"Error al obtener información. Código de estado: {respuesta.status_code}"

# Función para obtener información WHOIS de un dominio.
def obtener_info_whois(dominio):
    info = whois.whois(dominio)
    return str(info)

# Función para escanear puertos de una dirección IP.
def escanear_puertos(direccion_ip, puertos):
    resultados = []
    # Bucle para probar cada puerto en la lista.
    for puerto in puertos:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        resultado = sock.connect_ex((direccion_ip, puerto))
        if resultado == 0:
            resultados.append(f"Puerto {puerto} está abierto")
        sock.close()
    return resultados

# Función para obtener información técnica de un sitio web.
def obtener_info_sitio(url):
    result = builtwith.parse(url)
    # Extrae información específica del sitio.
    servidor = result.get('web-servers', ['Desconocido'])[0]
    cms = result.get('cms', ['Desconocido'])[0]
    lenguaje = result.get('programming-languages', ['Desconocido'])[0]
    js_framework = result.get('javascript-frameworks', ['Desconocido'])[0]
    return servidor, cms, lenguaje, js_framework

# Función para obtener información del certificado SSL de un dominio.
def obtener_info_ssl(dominio):
    try:
        contexto = ssl.create_default_context()
        with contexto.wrap_socket(socket.socket(), server_hostname=dominio) as s:
            s.connect((dominio, 443))
            cert = s.getpeercert()
            return cert
    except Exception as e:
        return f"Error al obtener información SSL: {str(e)}"

# Función para imprimir información del certificado SSL.
def imprimir_info_ssl(cert):
    print("Información del certificado SSL:")
    for campo, valor in cert.items():
        print(f"{campo}: {valor}")

# Función para guardar los resultados en diferentes formatos de archivo.
def guardar_resultados_en_archivo(resultados, formato):
    # Guarda los resultados en un archivo .txt, .csv o .json.
    if formato == "txt":
        with open("resultados.txt", "w") as archivo:
            archivo.write(resultados)
    elif formato == "csv":
        with open("resultados.csv", "w", newline='') as archivo:
            writer = csv.writer(archivo)
            for linea in resultados.split('\n'):
                writer.writerow([linea])
    elif formato == "json":
        with open("resultados.json", "w") as archivo:
            json.dump(resultados, archivo)

# Función para verificar la reputación de un dominio en VirusTotal.
def verificar_reputacion_virustotal(dominio):
    url = f"https://www.virustotal.com/api/v3/domains/{dominio}"
    headers = {"x-apikey": API_KEY_VIRUSTOTAL}
    try:
        respuesta = requests.get(url, headers=headers)
        respuesta.raise_for_status()
        datos = respuesta.json()
        if 'data' in datos and 'attributes' in datos['data'] and 'last_analysis_stats' in datos['data']['attributes']:
            reputacion = datos['data']['attributes']['last_analysis_stats']
            return f"Reputación del dominio '{dominio}': {reputacion['malicious']} detectados como maliciosos, {reputacion['suspicious']} sospechosos, {reputacion['harmless']} inofensivos."
        else:
            return "No se pudo obtener la reputación del dominio."
    except requests.exceptions.HTTPError as e:
        return f"Error al hacer la solicitud a VirusTotal: {str(e)}"

if __name__ == "__main__":
    dominio = input("Ingrese el dominio para buscar información: ")
    
    # Lista de herramientas disponibles para consulta.
    herramientas = [
        "mtr", "nping", "dnslookup", "reversedns", "whois", "ipgeo",
        "reverseiplookup", "httpheaders", "pagelinks", "aslookup"
    ]
    
    resultados_combinados = ""  # Almacena todos los resultados.

    # Bucle para ejecutar cada herramienta y recopilar resultados.
    for herramienta in herramientas:
        resultados_herramienta = obtener_resultados_herramienta(herramienta, dominio)
        print(f"\nResultados de {herramienta}:")
        print(resultados_herramienta)
        resultados_combinados += f"\nResultados de {herramienta}:\n{resultados_herramienta}"

    # Obtener y mostrar información adicional del dominio.
    informacion_dominio = obtener_informacion_dominio(dominio)
    print("\nInformación de dominio:")
    print(informacion_dominio)
    
    # Obtener y mostrar información WHOIS.
    informacion_whois = obtener_info_whois(dominio)
    print("\nInformación WHOIS:")
    print(informacion_whois)
    
    # Realizar y mostrar resultados del escaneo de puertos.
    try:
        direccion_ip = socket.gethostbyname(dominio)
        puertos = range(1, 25)
        resultados_escaneo = escanear_puertos(direccion_ip, puertos)
        print("\nResultados de escaneo de puertos:")
        print("\n".join(resultados_escaneo))
    except socket.gaierror:
        print("\nNo se pudo resolver la dirección IP del dominio.")
    
    # Obtener y mostrar información técnica del sitio web.
    servidor, cms, lenguaje, js_framework = obtener_info_sitio(f"https://{dominio}")
    print(f"\nSERVIDOR --> {servidor}")
    print(f"CMS DETECTADO --> {cms}")
    print(f"LENGUAJE DETECTADO --> {lenguaje}")
    print(f"JAVASCRIPT FRAMEWORK --> {js_framework}")
    
    # Obtener y mostrar información del certificado SSL.
    info_ssl = obtener_info_ssl(dominio)
    imprimir_info_ssl(info_ssl)

    # Verificar y mostrar la reputación del dominio en VirusTotal.
    reputacion = verificar_reputacion_virustotal(dominio)
    print(f"\n{reputacion}")
    
    # Preguntar al usuario el formato deseado para guardar los resultados.
    formato = input("\n¿En qué formato desea guardar los resultados? (txt/csv/json): ").lower()

    # Validar el formato y guardar los resultados.
    if formato not in ["txt", "csv", "json"]:
        print("Formato no válido. Se guardarán en formato TXT por defecto.")
        formato = "txt"
    guardar_resultados_en_archivo(resultados_combinados, formato)
