import csv
import re

def procesar_nmap(archivo_nmap, archivo_csv_salida):
    """
    Procesa un archivo Nmap en formato texto (.nmap) y extrae información relevante a un archivo CSV.

    Parámetros:
    archivo_nmap (str): El nombre del archivo de entrada de Nmap.
    archivo_csv_salida (str): El nombre del archivo CSV de salida con los datos procesados.
    """
    with open(archivo_nmap, "r", encoding="utf-8", errors="ignore") as f:
        contenido = f.read()

    # Dividimos por cada host (escaneo Nmap)
    hosts = contenido.split("Nmap scan report for ")[1:]

    # Abre el archivo CSV para escribir los datos
    with open(archivo_csv_salida, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            "Host", "Puerto", "Protocolo", "Estado",
            "Servicio", "Versión", "SO", "CVE VULNERABILIDADES"
        ])

        # Itera sobre cada host encontrado en el escaneo
        for host_data in hosts:
            lines = host_data.splitlines()
            ip = lines[0].strip()

            # Extrae información sobre los puertos y servicios
            for line in lines:
                match = re.match(
                    r"(\d+)/(\w+)\s+(\w+)\s+(\S+)\s*(.*)",
                    line
                )
                if match:
                    port, protocol, state, service, version = match.groups()

                    # Extraemos el sistema operativo (si está presente)
                    so = obtener_so(host_data)

                    # Buscamos las CVEs en el host (por script)
                    cves = obtener_cves(host_data)

                    # Escribimos la fila en el archivo CSV
                    writer.writerow([
                        ip, port, protocol, state,
                        service, version, so, cves
                    ])


def obtener_so(host_data):
    """
    Extrae el sistema operativo desde los datos de un host si está disponible.

    Parámetros:
    host_data (str): Datos completos de un solo host desde el archivo Nmap.

    Retorna:
    str: El sistema operativo encontrado o "N/A" si no se encuentra.
    """
    so_match = re.search(r"OS: (.+?)\n", host_data)
    return so_match.group(1) if so_match else "N/A"


def obtener_cves(host_data):
    """
    Extrae todas las CVEs encontradas en los scripts de Nmap.

    Parámetros:
    host_data (str): Datos completos de un solo host desde el archivo Nmap.

    Retorna:
    str: Cadena con las CVEs encontradas separadas por coma, o "N/A" si no se encuentran.
    """
    cves = re.findall(r"CVE-\d{4}-\d{4,7}", host_data)
    return ", ".join(set(cves)) if cves else "N/A"


# =========================
# EJECUCIÓN
# =========================
if __name__ == "__main__":
    archivo_nmap = "escaneo_intrusivo_VLAN.nmap"  # Archivo de entrada
    archivo_csv_salida = "reporte_07_vuln_nmap.csv"  # Archivo de salida CSV
    procesar_nmap(archivo_nmap, archivo_csv_salida)
