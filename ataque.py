import socket
import random
import time

# Configuração das variáveis
# Configuração das variáveis
target_ip = "10.1.121.213"  # Substitua pelo IP do seu servidor
port = 22  # Porta alvo (pode ser qualquer porta aberta)

# Criando um socket TCP
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)  # Definindo um tempo limite para a conexão

try:
    # Tentando conectar ao IP e porta alvo
    s.connect((target_ip, port))
    print(f"A porta {port} no IP {target_ip} está aberta.")
    packet_count = 1000  # Número de pacotes a serem enviados

    # Criando um socket raw
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    # Cabeçalho ICMP (simplificado)
    icmp_packet = b"\x08\x00\x00\x00"  # Tipo 8 (echo request), código 0

    while True:
        # Gerando um ID aleatório
        random_id = random.randint(1, 65535)
        # Criando o pacote ICMP completo
        packet = icmp_packet + random_id.to_bytes(2, byteorder='big') + random_id.to_bytes(2, byteorder='big')
        # Enviando o pacote
        s.sendto(packet, (target_ip, port))
        print("Pacote enviado")
        time.sleep(0.01)  # Ajuste o tempo de espera conforme necessário

        if packet_count == 0:
            break
except socket.timeout:
    print(f"A porta {port} no IP {target_ip} está fechada (tempo limite esgotado).")
except socket.error:
    print(f"A porta {port} no IP {target_ip} está fechada.")
finally:
    # Fechando o socket
    s.close()