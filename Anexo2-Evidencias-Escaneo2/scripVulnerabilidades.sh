#!/bin/bash
#
# Escaneo Nmap/Nikto por VLAN:
#  - Recorre un rango de VLANs (40.30.0.x a 40.30.20.x por defecto)
#  - Descubre qué hosts están encendidos en cada VLAN
#  - Para cada host, ejecuta los escaneos de nmap/nikto catalogados
#
# REQUIERE:
#   - sudo / root
#   - nmap instalado
#   - nikto (opcional, si quieres usarlo)
#

set -euo pipefail

# ==============
# Parámetros 
# ==============
VLAN_BASE="20.20"          # Base de las VLANs: xx.xx.0.2/32
VLAN_START=2              # VLAN inicial -> xx.xx.x.3/32
VLAN_END=3

             # VLAN final   ->xx.xx.x.3/32
OUTDIR_ROOT="./nmap_vlans_$(date +%Y%m%d_%H%M%S)"

# Opciones de descubrimiento
DISCOVERY_OPTS="-sn -n"    # -sn: ping scan, -n: sin resolución DNS

# ============================
# Función de ayuda
# ============================
usage() {
  cat <<EOF
Uso: sudo $0 [opciones]

Opciones:
  -b <base>     Base de VLAN (por defecto: 10.10)  -> genera 40.30.X.Y
  -s <inicio>   VLAN inicial (por defecto: 0)
  -e <fin>      VLAN final   (por defecto: 20)
  -o <outdir>   Directorio raíz de resultados (por defecto: $OUTDIR_ROOT)
  -h            Mostrar esta ayuda

Ejemplo:
  sudo $0 -b 10.10 -s 0 -e 20 -o ./resultados_nmap
EOF
}

# ============================
# Parámetros Script
# ============================
while getopts ":b:s:e:o:h" opt; do
  case $opt in
    b) VLAN_BASE="$OPTARG" ;;
    s) VLAN_START="$OPTARG" ;;
    e) VLAN_END="$OPTARG" ;;
    o) OUTDIR_ROOT="$OPTARG" ;;
    h) usage; exit 0 ;;
    *) usage; exit 1 ;;
  esac
done

# ============================
# Validaciones básicas
# ============================
if [[ $EUID -ne 0 ]]; then
  echo "[ERROR] Debes ejecutar este script con sudo o como root."
  exit 1
fi

if ! command -v nmap >/dev/null 2>&1; then
  echo "[ERROR] nmap no está instalado. Instálalo e inténtalo de nuevo."
  exit 2
fi

NIKTO_BIN=""
if command -v nikto >/dev/null 2>&1; then
  NIKTO_BIN="$(command -v nikto)"
  HAS_NIKTO=1
else
  HAS_NIKTO=0
  echo "[AVISO] nikto no está instalado. Se omitirán los escaneos web con nikto."
fi

mkdir -p "$OUTDIR_ROOT"
echo "[INFO] Directorio raíz de resultados: $OUTDIR_ROOT"
echo "[INFO] Rango de VLANs: $VLAN_BASE.$VLAN_START.x  ->  $VLAN_BASE.$VLAN_END.x"

# ============================
# escanear un host
# ============================
scan_host() {
  local IP="$1"
  local HOST_DIR="$OUTDIR_ROOT/$IP"

  mkdir -p "$HOST_DIR"
  echo "------------------------------------------------------------"
  echo " Escaneando host $IP ---  Resultados en: $HOST_DIR"
  echo "------------------------------------------------------------"

  # 01 - Discovery focalizado (puertos 22,80,443)
nmap -Pn -n -sS -sV -O -p- -PR --send-eth -R \
  --script "vuln,auth,brute,ssl-enum-ciphers,http-vuln*,nbstat,smb-os-discovery" \
  -T4 --max-retries 0 \
  -oA "$HOST_DIR/scaneo_Intrusivo" "$IP"

 
  # 09 - Nikto (scanner web), si está disponible
  if [[ "$HAS_NIKTO" -eq 1 ]]; then
    echo "[INFO] Ejecutando nikto contra http://$IP"
   "$NIKTO_BIN" -h "http://$IP" -output "$HOST_DIR/09_nikto_http.txt" || true

    echo "[INFO] Ejecutando nikto contra https://$IP (si aplica)"
    "$NIKTO_BIN" -h "https://$IP" -output "$HOST_DIR/09_nikto_https.txt" || true
  fi

  echo "[OK] Escaneos completados para $IP"
}

# ============================
# Bucle principal por VLAN
# ============================
for VLAN_ID in $(seq "$VLAN_START" "$VLAN_END"); do
  SUBNET="$VLAN_BASE.$VLAN_ID.0/24"
  VLAN_DIR="$OUTDIR_ROOT/VLAN_${VLAN_BASE}_${VLAN_ID}"
  mkdir -p "$VLAN_DIR"

  echo
  echo "================================================================="
  echo " Equipos encendidos en VLAN $SUBNET"
  echo "================================================================="

  # Descubrimiento de hosts encendidos (Up)
  #
  # - Utilizamos salida en formato grepable (-oG) para extraer IPs "Up"
  #

  # # Lista de IPs excluidas por VLAN (por ejemplo: gateways y firewalls)
  EXCLUDE_IPS="--exclude 10.10.$VLAN_ID.1,10.10.$VLAN_ID.254"
  LIVE_HOSTS=()
  while IFS= read -r ip; do
    LIVE_HOSTS+=("$ip")
#  done < <( nmap $DISCOVERY_OPTS "$SUBNET" -oG - | awk '/Up$/{print $2}' )
  done < <( nmap $DISCOVERY_OPTS $EXCLUDE_IPS "$SUBNET" -oG - | awk '/Up$/{print $2}' ) 

  if [[ ${#LIVE_HOSTS[@]} -eq 0 ]]; then
    echo "[AVISO] No se encontraron hosts encendidos en $SUBNET"
    continue
  fi

  echo "[INFO] Hosts encendidos en $SUBNET:"
  for ip in "${LIVE_HOSTS[@]}"; do
    echo "  - $ip"
  done

  # Escaneo detallado por host
  for ip in "${LIVE_HOSTS[@]}"; do
    scan_host "$ip"
  done

done

echo "================================================================="

