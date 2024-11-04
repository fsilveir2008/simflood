# Projeto de Monitoramento e Defesa de Rede

Este projeto implementa um sistema de monitoramento e defesa contra ataques de rede, especificamente para identificar e mitigar ataques do tipo **simflood**. O projeto consiste em dois scripts principais, `defesa.py` e `ataque.py`, que monitoram o tráfego de rede para detecção de ataques e simulam ataques em um alvo específico, respectivamente.

## Funcionalidades

- **Monitoramento de Pacotes Ethernet**: O script `defesa.py` captura e analisa pacotes de rede para identificar padrões de ataque.
- **Defesa Automática**: Bloqueia automaticamente os IPs que excedem o limite de pacotes permitidos, mitigando possíveis ataques de negação de serviço (DoS).
- **Simulação de Ataque ICMP**: O script `ataque.py` simula um ataque ICMP (simflood) em um IP alvo para fins de teste e desenvolvimento.

## Pré-requisitos

### Sistema Operacional

- **Sistema Operacional**: Este projeto foi desenvolvido para sistemas Unix-like (Linux e macOS). Não é compatível com Windows devido à necessidade de sockets de baixo nível (`AF_PACKET`) e ao uso de `ufw` para o gerenciamento de firewall.

### Bibliotecas e Dependências

O projeto utiliza bibliotecas padrão do Python, como `socket`, `struct`, `time`, e `subprocess`. Abaixo estão as dependências específicas de cada script.

#### `defesa.py`

- **Permissões**: Este script requer privilégios de superusuário para capturar pacotes de rede e manipular regras de firewall.
- **Dependências de Software**:
  - `ufw` (Uncomplicated Firewall): Necessário para bloquear IPs suspeitos automaticamente.
  - **Python 3.x**: Inclui bibliotecas nativas usadas no script (`socket`, `struct`, `time`, `subprocess`).

#### `ataque.py`

- **Permissões**: Necessário ser executado com privilégios elevados, pois utiliza sockets `RAW`.
- **Dependências de Software**:
  - **Python 3.x**: Inclui bibliotecas nativas utilizadas no script (`socket`, `random`, `time`).

### Instalação de Dependências

Caso o `ufw` não esteja instalado no sistema, instale-o com o comando:

```bash
sudo apt-get install ufw  # Para sistemas Debian-based
sudo ufw enable # Para começar o monitoramento do UFW
```

### Para execução...
1. Inicialize o monitoramento de defesa para proteger o sistema:
```bash
sudo python3 defesa.py
```
2. Lembre-se de configurar os parâmetros `target_ip` e o `port` com o IP e Porta de destino para direcionar o ataque. Para iniciar o ataque, execute o comando abaixo:
```bash
sudo python3 ataque.py
```

### Observações Importantes
- **Firewall**: Este projeto utiliza o ufw para bloqueio de IPs. Certifique-se de que o ufw esteja configurado e ativo no sistema.
- **Propósito Educacional**: Este projeto foi criado para estudos e simulação de ataques em ambiente controlado. Utilize-o de forma ética e responsável.
