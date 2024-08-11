
# Indice

__[1 Firewall en Sistemas Operativos](#1-Firewall-en-Sistemas-Operativos)__

__[2 Cookies Hacking](#2-Cookies-Hacking)__



# 1 Firewall en Sistemas Operativos
## 1.1. Introduccion a los Firewalls
### Definición y Función

__¿Qué es un Firewall?__
Dispositivo o software diseñado para controlar el tráfico de red.
Actúa como una barrera entre redes internas y externas.

__¿Qué es iptables?__
iptables es una interfaz de línea de comandos que se utiliza para configurar el filtrado de paquetes y la administración de reglas de firewall en el kernel de Linux. Permite definir cómo deben ser manejados los paquetes de red basándose en varias características como la dirección IP de origen y destino, el puerto, el protocolo y el estado de la conexión.

__¿Cómo Protege una Red o un Sistema?__
Filtrado de Paquetes: Examina y permite o bloquea paquetes de datos. (HTTP (puerto 80) y el paquete es para el puerto 22 (SSH))

```bash
    # Permitir tráfico HTTP
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT

    # Bloquear tráfico FTP
    iptables -A INPUT -p tcp --dport 21 -j DROP
```

Inspección de Estado: Monitorea el estado de las conexiones y asegura que el tráfico sea legítimo.(Accept y Deny)
```bash
    # Permitir conexiones entrantes relacionadas y establecidas
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # Bloquear nuevas conexiones en el puerto 22 (SSH)
    iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j DROP
```

Filtrado de Aplicaciones: Controla el tráfico basado en aplicaciones específicas. (acceso solo a sitios de trabajo y bloquea redes sociales)
```bash
    iptables -A INPUT -p tcp --dport 80 -m string --string "badword" --algo bm -j DROP
```
    
### Tipos de Firewalls

__Firewalls de Red__
    Protegen toda una red de posibles amenazas externas.
    Se sitúan en la frontera de la red. (Cisco ASA (Adaptive Security Appliance))
__Firewalls de Host__
    Protegen equipos individuales.
    Se instalan directamente en el dispositivo que protegen. (Windows Defender Firewall)
__Firewalls Basados en Software y Hardware__
    Software: Instalados en sistemas operativos; flexibles y configurables.
    Hardware: Dispositivos independientes; más robustos y especializados. (PfSense)

### Importancia de los Firewalls en la Seguridad Informática
__Prevención de Accesos No Autorizados__
Bloqueo de intentos de acceso no deseado a la red o sistema.
__Control de Tráfico de Red__
Regulación del flujo de datos y prevención de ataques como DDoS.


## 1.2. Componentes de un Firewall
### Políticas y Reglas
__Definición y Propósito__
Políticas: Directrices de seguridad establecidas por la organización.
Reglas: Implementaciones específicas de políticas en el firewall.
Aplicación: Configuración manual o mediante scripts en el firewall.
__Ejemplos de Políticas Comunes__
Permitir solo tráfico HTTP y HTTPS.
Bloquear acceso a redes sociales durante horas laborales.
Permitir conexiones SSH solo desde direcciones IP específicas.

### Listas de Control de Acceso (ACL)
__Definición y Propósito__
Definición: Conjunto de reglas que controlan el tráfico de red.
Propósito: Restringir el acceso a recursos específicos en la red.

__Ejemplos de ACL en Acción__
Permitir tráfico solo desde la subred 192.168.1.0/24.
Bloquear todo el tráfico entrante en el puerto 23 (Telnet).
Permitir acceso a un servidor web solo desde la IP 203.0.113.10.

### Registro y Monitoreo
__Cómo se Registran los Eventos__
Registros: Documentación de eventos de tráfico y seguridad.
Métodos: Archivos de log, bases de datos, sistemas de SIEM (Security Information and Event Management).

__Herramientas de Monitoreo y Análisis__
Herramientas de Monitoreo: Wireshark, Nagios.
Herramientas de Análisis: Splunk, ELK Stack (Elasticsearch, Logstash, Kibana).



## 1.3. Herramientas Comunes de Hacking de Firewalls
### Nmap para Escaneo de Puertos y Servicios
Nmap (Network Mapper) es una herramienta de código abierto utilizada para el descubrimiento de redes y auditorías de seguridad, permite a los profesionales en ciberseguridad identificar puertos abiertos y los servicios que se ejecutan en ellos, lo cual es crucial para encontrar puntos vulnerables en un firewall.

__Funciones Principales__
Escaneo de Puertos: Identifica qué puertos están abiertos, cerrados o filtrados.
Detección de Servicios: Identifica los servicios que se están ejecutando en los puertos abiertos y sus versiones.
Detección de SO: Intenta identificar el sistema operativo del objetivo.

Ejemplo:
```bash
    nmap -sS -p 1-65535 192.168.1.1
```

### Hping3 para Generación de Paquetes Personalizados

Hping3 es una herramienta de red de línea de comandos utilizada para generar y enviar paquetes TCP/IP personalizados. Utilizada para pruebas de seguridad como ataques DDoS, escaneo de puertos, y pruebas de firewall.

__Funciones__

Generación de Paquetes: Permite crear paquetes TCP, UDP, ICMP y RAW-IP personalizados.
Pruebas de Firewall: Envía paquetes con diferentes configuraciones para probar cómo un firewall maneja el tráfico.
Escaneo de Puertos: Similar a Nmap pero con mayor control sobre los paquetes enviados.

Fragmentación de Paquetes con Hping3:
```bash
hping3 -S -p 80 -c 1 192.168.1.1
```
Este comando envía un solo paquete SYN al puerto 80 del host 192.168.1.1, simulando una solicitud de conexión.



## 1.4. Técnicas de Bypass de Firewalls

### Determining Firewall Rules
https://nmap.org/book/determining-firewall-rules.html


__Escaneo SYN__

El escaneo SYN es un método común de escaneo de puertos que utiliza Nmap para determinar si un puerto está abierto, cerrado o filtrado. Funciona enviando un paquete SYN (que inicia una conexión TCP) y luego analiza la respuesta sin completar la conexión.

- Puerto abierto: Si recibe un paquete SYN-ACK, el puerto está abierto.
- Puerto cerrado: Si recibe un paquete RST, el puerto está cerrado.
- Puerto filtrado: Si no recibe respuesta o recibe un error ICMP, el puerto está filtrado.

```bash
nmap -sS -T4 scanme.nmap.org
```


__Escaneo ACK__

El escaneo ACK se utiliza principalmente para mapear reglas de firewall y determinar si los puertos están filtrados o no. No revela si un puerto está abierto o cerrado, sino si está filtrado por un firewall.

-   Filtrado: No hay respuesta o se recibe un error ICMP.
No filtrado: Respuesta con un paquete RST.

```bash
nmap -sA scanme.nmap.org
```



__Escaneo UDP__
El escaneo UDP examina puertos que utilizan el protocolo UDP en lugar de TCP. Este tipo de escaneo es más lento y menos fiable que el escaneo TCP porque las respuestas de los puertos UDP pueden ser más difíciles de interpretar.

- Puerto abierto: Si recibe una respuesta del servicio.
- Puerto cerrado: Si recibe un paquete ICMP "port unreachable".
- Puerto filtrado: Si no recibe ninguna respuesta.

```bash
nmap -sU -p50-59 scanme.nmap.org
nmap -sV -sU -p50-59 scanme.nmap.org

nping -c 5 --delay 1 -p 80 --tcp playground
```

__IP ID Tricks__

El IP ID es un campo en el encabezado de un paquete IP que se utiliza para identificar fragmentos de un paquete más grande, permitiendo que estos fragmentos se reensamblen correctamente en el destino. Algunos sistemas operativos incrementan este valor secuencialmente para cada paquete enviado. Esta predictibilidad puede ser explotada para realizar técnicas de escaneo como el Idle Scan.

Idle Scan: Una técnica de escaneo que utiliza un "zombie" (un dispositivo con secuencia predecible de IP ID) para enviar paquetes al objetivo. El atacante observa cómo cambian los valores de IP ID en el "zombie" para determinar si los puertos en el objetivo están abiertos o cerrados, sin que el objetivo detecte la actividad del atacante.

```bash
nmap -sI zombie_host target_host
```



### Bypassing Firewall Rules
https://nmap.org/book/determining-firewall-rules.html

Utilizar proxies y redes Tor para ocultar la dirección IP de origen y eludir los filtros de firewall que bloquean direcciones IP específicas.
Los proxies actúan como intermediarios que reenvían las solicitudes al servidor final, mientras que Tor es una red que anonimiza el tráfico de internet.


__Exotic Scan Flags__

Los Exotic Scan Flags se refieren a escaneos que utilizan combinaciones inusuales o no estándar de flags TCP en los paquetes SYN enviados al objetivo. Estas técnicas pueden evadir algunas configuraciones de firewall o sistemas de detección de intrusos (IDS) al no utilizar las secuencias típicas de flags utilizadas en conexiones TCP regulares. Algunos de estos escaneos incluyen flags como FIN, Xmas, y Null.

FIN Scan:
Envía paquetes con el flag FIN, que indica que el emisor ha terminado de enviar datos. Un puerto cerrado debería responder con un paquete RST, mientras que un puerto abierto no debería responder en absoluto.
nmap -sF scanme.nmap.org

Xmas Scan:
Envía paquetes con los flags FIN, PSH, y URG activados, lo que se conoce como un "Xmas Tree" debido a que todos estos bits están encendidos (como luces en un árbol de Navidad).
nmap -sX scanme.nmap.org

Null Scan:
Envía paquetes sin ningún flag activado, lo que puede confundir a algunos sistemas de detección o firewalls.
nmap -sN scanme.nmap.org



__Manipulacion de Source Port__

La Manipulación de Source Port implica cambiar manualmente el puerto de origen del escaneo. Esto se utiliza para intentar evadir firewalls que permiten el tráfico basado en el puerto de origen. Por ejemplo, algunos firewalls podrían permitir tráfico que parece provenir del puerto 53 (DNS), asumiendo que se trata de tráfico DNS legítimo.

nmap --source-port 53 scanme.nmap.org


__Ataque IPv6__

IPS Ingreso por sus alternativas de direccion IPv4 y IPv6.

```bash
http://127.1/    

http://::1/
http://[::1]:80/

```

__Proxies__

Proxies Web para utilizar servicios de proxy para redirigir el tráfico a través de diferentes servidores.
Redes Tor que encapsular el tráfico en múltiples capas de cifrado y enviarlo a través de una serie de nodos para anonimizar la fuente.


```bash
curl -x http://proxyserver:port http://targetwebsite
```
Este comando envía una solicitud HTTP a targetwebsite a través de un servidor proxy especificado por proxyserver:port.

Uso de Tor con Torify:
```bash
apt install tor
sudo systemctl start/enable/status tor
nano /etc/tor/torrc
systemctl restart tor

curl --socks5 localhost:9050 http://check.torproject.org/
nmap -sT -Pn --proxy socks5://127.0.0.1:9050 <target>

```
Este comando envía una solicitud HTTP a targetwebsite a través de la red Tor, anonimizando la fuente del tráfico.





# 2 Cookies Hacking
## 2.1. Introducción a las Cookies
Las cookies son pequeños archivos de texto que se almacenan en el dispositivo del usuario cuando visitan un sitio web.
El objetivo de una cookie es 
Gestión de Sesiones: Mantener al usuario autenticado mientras navega.
Personalización: Almacenar preferencias del usuario, como idioma o tema.
Seguimiento y Análisis: Monitorizar el comportamiento del usuario para optimizar la experiencia web.
__Tipos__
Cookies de Sesión: Temporales, se eliminan al cerrar el navegador, se mantiene la sesión activa del usuario.
Cookies Persistentes: Permanecen en el dispositivo hasta una fecha de caducidad establecida., recuerda preferencias o autenticación en visitas futuras.
Cookies de Terceros: Descripción: Generadas por dominios distintos al que el usuario visita, publicidad y seguimiento a través de múltiples sitios.


## 2.2. Fundamentos de Seguridad en Cookies

### Propiedades de las Cookies
__HttpOnly:__ Restringe el acceso a las cookies desde JavaScript del lado del cliente. Previene ataques de Cross-Site Scripting (XSS).

__Secure:__ Asegura que la cookie solo se transmita a través de HTTPS. Evita la intercepción de cookies en conexiones no seguras.

__SameSite:__ Controla cuándo las cookies se envían en solicitudes cross-site. Mitiga los riesgos de Cross-Site Request Forgery (CSRF).

    - Strict: Sólo se envía en solicitudes al mismo sitio.
    - Lax: Se envía en algunas solicitudes de navegación entre sitios.
    - None: Se envía en todas las solicitudes cross-site (requiere Secure).


### Almacenamiento y Gestión de Cookies

__Almacenamiento__
Las cookies se almacenan en el navegador del usuario como archivos de texto.
Cada cookie contiene un nombre, valor, y atributos opcionales como expiración y dominio.

__Gestión__
Los navegadores permiten ver, editar y eliminar cookies a través de herramientas de desarrollador.
El servidor web envía cookies al navegador a través de cabeceras HTTP con las propiedades configuradas.

### Riesgos y Vulnerabilidades Comunes
__Secuestro de Sesiones__
Descripción: Ataque donde un atacante roba cookies de sesión para suplantar la identidad del usuario. Utilizar las propiedades HttpOnly y Secure.

__Cross-Site Scripting (XSS)__
Inyección de scripts maliciosos que pueden acceder a cookies no protegidas.
Prevención: Habilitar HttpOnly en cookies sensibles.

__Cross-Site Request Forgery (CSRF)__
Ataque donde un usuario es inducido a realizar acciones no deseadas en una aplicación autenticada.
Prevención: Configurar SameSite adecuadamente.


## 2.3. Técnicas de Ataque en Cookies
### Secuestro de Cookies (Cookie Hijacking)
Un ataque donde el atacante intercepta y roba las cookies de sesión de un usuario.
Ejemplo: Ponerse a escuchar de tráfico en redes no seguras (por ejemplo, Wi-Fi público). Wireshark (PoC)

### Manipulación de Cookies (Cookie Manipulation)
La modificación deliberada de los valores de las cookies para alterar el comportamiento de una aplicación.
Ejemplo: Cambiar una cookie de "usuario=normal" a "usuario=admin" para obtener privilegios elevados. DVWA (PoC)

### Cross-Site Scripting (XSS) y Cookies
Una vulnerabilidad que permite a un atacante inyectar scripts maliciosos en la página web de un usuario. DVWA (PoC)
Ejemplo: Un script inyectado en una página web puede capturar y enviar cookies a un servidor controlado por el atacante.  DVWA (PoC)

### Cross-Site Request Forgery (CSRF) y Cookies
Un ataque que engaña a un usuario autenticado para que ejecute acciones no deseadas en una aplicación web.
Explicación: Al forzar al usuario a enviar una solicitud no deseada a un servidor donde está autenticado, el servidor procesa la solicitud como válida debido a la cookie de sesión existente.  DVWA (PoC)




display_errors = On

error_reporting = E_ALL



GRANT ALL PRIVILEGES ON database.* TO 'cisco'@'localhost' IDENTIFIED BY 'password';
FLUSH PRIVILEGES;

http://192.168.1.9/DVWA/vulnerabilities/xss_r/?name=%3Cscript%3Ealert%28document.cookie%29%3C%2Fscript%3E#



# Filosofia del Hacking
# Cripgrafia

### Ofuscación de Payloads (Cargas Útiles)
Modificar el contenido de las cargas útiles de los paquetes para evitar la detección por parte de firewalls y sistemas de detección de intrusiones (IDS).
Las técnicas de ofuscación pueden incluir el cifrado, la codificación o la modificación del formato del payload.
__Técnicas__
Cifrado y Codificación: Cifrar o codificar la carga útil para que no sea reconocida como maliciosa.
Polimorfismo: Modificar el código de la carga útil en cada instancia para evitar la firma de detección basada en patrones.
```bash
nc -l -p 4444
nc <server_ip> 4444
```

https://github.com/pprugger/Cryptcat-1.3.0-Win-10-Release?tab=readme-ov-file

```bash
cryptcat -k mysecretkey -l -p 4444
cryptcat -k mysecretkey <server_ip> 4444
```



# La metodología OSINT
# CVEs y CEWs


# Phising de redes sociales
# Informatica Forense, legalidades y procedimientos


# Anonimato Dark Web Deep Web
### Uso de Proxies y Redes Tor
Utilizar proxies y redes Tor para ocultar la dirección IP de origen y eludir los filtros de firewall que bloquean direcciones IP específicas.
Los proxies actúan como intermediarios que reenvían las solicitudes al servidor final, mientras que Tor es una red que anonimiza el tráfico de internet.
__Técnicas__
Proxies Web: Utilizar servicios de proxy para redirigir el tráfico a través de diferentes servidores.
Redes Tor: Encapsular el tráfico en múltiples capas de cifrado y enviarlo a través de una serie de nodos para anonimizar la fuente.

```bash
curl -x http://proxyserver:port http://targetwebsite
```
Este comando envía una solicitud HTTP a targetwebsite a través de un servidor proxy especificado por proxyserver:port.

Uso de Tor con Torify:
```bash
apt install tor
sudo systemctl start/enable/status tor
nano /etc/tor/torrc
systemctl restart tor

curl --socks5 localhost:9050 http://check.torproject.org/
nmap -sT -Pn --proxy socks5://127.0.0.1:9050 <target>

```
Este comando envía una solicitud HTTP a targetwebsite a través de la red Tor, anonimizando la fuente del tráfico.



# Exploits

# Seguridad Informatica Avanzada