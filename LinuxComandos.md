# Actualiza la lista de paquetes disponibles y sus versiones
apt update

# Descarga e instala las versiones más recientes de los paquetes instalados
apt upgrade

# Inicia el servicio SSH para permitir conexiones remotas al servidor
systemctl start ssh

# Habilita el servicio SSH para que se inicie automáticamente al arrancar el sistema
systemctl enable ssh

# Instala tmux (multiplexor de terminal), git (control de versiones) y vim (editor de texto)
apt install tmux git vim