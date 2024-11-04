import socket
import struct
import time
import subprocess

# Crie um socket raw Ethernet para capturar pacotes (Unix-like systems)
try:
    raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
except AttributeError:
    print("Este script só pode ser executado em sistemas Unix-like.")
    exit(1)

print("Aguardando pacotes Ethernet...")

# Dicionário para rastrear o número de pacotes por IP
packet_count = {}
# Limite de pacotes por segundo para considerar como ataque
PACKET_LIMIT = 5

while True:
    try:
        # Capture um pacote Ethernet
        packet, addr = raw_socket.recvfrom(65535)

        # Analise o cabeçalho Ethernet
        eth_header = packet[:14]
        eth_payload = packet[14:]

        eth_dest_mac, eth_src_mac, eth_type = struct.unpack("!6s6sH", eth_header)

        # Verificar se o pacote é IPv4 (EtherType 0x0800)
        if eth_type == 0x0800:
            ip_header = eth_payload[:20]
            ip_version, ip_tos, ip_length, ip_id, ip_flags, ip_ttl, ip_protocol, ip_checksum, ip_src, ip_dest = struct.unpack("!BBHHHBBH4s4s", ip_header)

            ip_src_str = socket.inet_ntoa(ip_src)

            # Atualizar o contador de pacotes para o IP de origem
            current_time = time.time()
            if ip_src_str not in packet_count:
                packet_count[ip_src_str] = []
            packet_count[ip_src_str].append(current_time)

            # Remover entradas antigas (mais de 1 segundo)
            packet_count[ip_src_str] = [timestamp for timestamp in packet_count[ip_src_str] if current_time - timestamp < 1]

            # Verificar se o limite de pacotes foi excedido
            if len(packet_count[ip_src_str]) > PACKET_LIMIT:
                print(f"Detectado ataque de simflood do IP: {ip_src_str}")
                # Bloquear o IP usando ufw
                subprocess.run(["sudo", "ufw", "deny", "from", ip_src_str])
                # Limpar o contador para evitar múltiplos bloqueios
                packet_count[ip_src_str] = []

            print("Cabeçalho IP:")
            print(f"Endereço de origem: {ip_src_str}")
            print(f"Endereço de destino: {socket.inet_ntoa(ip_dest)}")
            print(f"Protocolo: {ip_protocol}")
            print("--------------------")

            # Verificar se o protocolo é TCP (protocolo 6) ou UDP (protocolo 17)
            if ip_protocol == 6 or ip_protocol == 17:
                if ip_protocol == 6:
                    tcp_header = eth_payload[20:40]
                    src_port, dest_port, sequence, ack_num, offset_flags = struct.unpack("!HHIIB", tcp_header)
                    offset = (offset_flags >> 4) * 4

                    print("Cabeçalho TCP:")
                    print(f"Porta de origem: {src_port}")
                    print(f"Porta de destino: {dest_port}")
                    print(f"Número de Sequência: {sequence}")
                    print(f"Número de Ack: {ack_num}")
                    print("--------------------")

                if ip_protocol == 17:
                    udp_header = eth_payload[20:28]
                    src_port, dest_port, udp_length, udp_checksum = struct.unpack("!HHHH", udp_header)

                    print("Cabeçalho UDP:")
                    print(f"Porta de origem: {src_port}")
                    print(f"Porta de destino: {dest_port}")
                    print(f"Tamanho: {udp_length}")
                    print("--------------------")
        print("====================")
    except Exception as e:
        print(f"Erro ao processar pacote: {e}")


'''
O uso desses símbolos, como "!BBHHHBBH4s4s", está relacionado ao empacotamento e desempacotamento de dados em uma estrutura de pacote em uma comunicação de rede ao trabalhar com sockets raw em Python. Essa sequência de caracteres é uma string de formato que descreve como os dados brutos devem ser interpretados ou construídos.

Aqui está o que cada símbolo significa:

- `!`: Indica que os dados devem ser interpretados na ordem nativa do host (endianess). Isso significa que os dados serão lidos ou escritos na ordem em que são representados na arquitetura do computador em que o código está sendo executado.

- `BBHHHBBH4s4s`: Essa parte da string de formato descreve a estrutura específica dos dados no pacote. Cada letra ou símbolo corresponde a um campo de dados na estrutura. Aqui está uma correspondência:

  - `B`: Um byte (8 bits).
  - `H`: Um short integer (16 bits).
  - `4s`: Uma sequência de 4 bytes (32 bits) interpretada como uma string.
  - `4s`: Outra sequência de 4 bytes (32 bits) interpretada como uma string.

A sequência "!BBHHHBBH4s4s" pode ser usada para descrever um pacote de dados que consiste em:

- Um byte (B)
- Outro byte (B)
- Um short integer (H)
- Um short integer (H)
- Um short integer (H)
- Um byte (B)
- Outro byte (B)
- Um short integer (H)
- Duas sequências de 4 bytes (4s e 4s)

Essa sequência de formato é útil ao lidar com a análise de pacotes em uma comunicação de rede de baixo nível, como em sockets raw, onde você precisa especificar como os dados brutos são organizados para extrair informações significativas deles ou criar pacotes para envio. Cada símbolo na sequência de formato corresponde a um campo de dados específico no pacote.
'''
