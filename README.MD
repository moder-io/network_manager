# Administrador de Red en Python

Este proyecto es un administrador de red básico desarrollado en Python. Permite escanear dispositivos conectados en una red local, realizar ping a esos dispositivos, escanear puertos abiertos y realizar un traceroute. Es una herramienta útil para administradores de red y entusiastas que desean monitorear su red local.

## Funcionalidades Generales

- **Escaneo de dispositivos conectados**: Descubre todos los dispositivos conectados en una red local.

- **Ping**: Comprueba si un dispositivo responde a solicitudes de ping.

- **Escaneo de puertos**: Identifica puertos abiertos en dispositivos conectados.

- **Traceroute**: Muestra la ruta que siguen los paquetes hacia un dispositivo específico.

- **Escaneo de sistema operativo (OS Fingerprinting)**: Identifica el sistema operativo de un dispositivo en la red, devolviendo información detallada sobre su versión si está disponible.

- **Escaneo SYN de puertos**: Verifica si un puerto específico en un dispositivo está abierto, cerrado o filtrado. Este método de escaneo es rápido y efectivo para identificar el estado de los puertos.

- **Extracción de banner**: Obtiene el banner de un servicio que se ejecuta en un puerto específico de un dispositivo, revelando información útil sobre el software que se está ejecutando.

- **Escaneo de vulnerabilidades**: Detecta vulnerabilidades conocidas en los servicios de un dispositivo en la red, proporcionando información sobre posibles debilidades de seguridad.

- **Escaneo UDP de puertos**: Escanea puertos UDP de un dispositivo para determinar si están abiertos, cerrados o filtrados. El escaneo UDP es crucial para identificar servicios que utilizan este protocolo.

- **Enumeración DNS**: Obtiene diferentes registros DNS asociados a un dominio, como registros A, MX, CNAME, NS, entre otros, proporcionando información sobre la infraestructura de red del dominio.

- **Escaneo de subdominios**: Busca y verifica la existencia de subdominios asociados a un dominio principal mediante la prueba de varias combinaciones de subdominios.

- **Escaneo de versiones de servicios**: Identifica la versión del software que se está ejecutando en un puerto específico de un dispositivo, proporcionando detalles sobre el nombre y la versión del servicio.

- **Escaneo paralelo de puertos**: Realiza un escaneo simultáneo de varios puertos en un dispositivo, mejorando la eficiencia del escaneo al ejecutar múltiples pruebas en paralelo.

- **Mapeo de red**: Identifica todos los dispositivos conectados en una red, mostrando sus direcciones IP, direcciones MAC y, si es posible, el fabricante del dispositivo.

## Exportacion a JSON
- Los datos del escaneo serán guardados en formato JSON en la carpeta ´results´ con toda la información

## Requisitos

- Python 3.6 o superior
- Npcap si estas en windows:
  - `https://npcap.com/#download`
- Dependencias listadas en:
  - `requirements.txt`

## Instalación

1. **Clona el repositorio:**
   ```bash
   git clone https://github.com/moder-io/network_manager.git

2. **Ejecuta el archivo run.bat si estas en windows, sino:**
   ```bash
   python scripts/main.py
