# dhcp2veyon

Este sistema tem como objetivo converter dados de leases DHCP para um formato JSON compatível com a configuração do Veyon. 
A ferramenta permite filtrar dados por rede e sala, e pode também ser configurada para exibir apenas a sala à qual um IP específico pertence.

## Funcionalidades

- **Conversão de arquivos de leases DHCP para o formato JSON do Veyon**: A partir de um arquivo de leases DHCP, o sistema gera um arquivo JSON no formato esperado pelo Veyon.
- **Filtragem por rede (CIDR)**: É possível especificar uma ou mais redes em CIDR (por exemplo, `192.168.1.0/24`) para filtrar as máquinas e salas que serão incluídas na configuração.
- **Filtragem por endereço IP**: Com a opção `-a`, é possível filtrar os resultados para incluir apenas a sala onde o IP fornecido está presente.
- **Exclusão de outras salas**: Quando a opção `-a` é utilizada, o sistema garante que apenas os hosts da sala associada ao IP fornecido sejam exibidos, excluindo as demais salas.
- **Retorno vazio em caso de IP inválido**: Quando um IP fornecido não pertence a nenhuma rede e a opção `--all` não está ativa, o sistema retorna uma configuração vazia, mantendo a estrutura do JSON Veyon com o campo `JsonStoreArray` vazio.

## Instalação

### Requisitos
- Python 3.6 ou superior

### Instalação das dependências

Não há dependências.

### Arquivo de leases DHCP

A entrada do sistema deve ser um arquivo de leases DHCP, que pode ser obtido diretamente de um servidor DHCP ou exportado de um sistema que o forneça. A entrada pode ser um caminho local para o arquivo ou uma URL.

## Uso da versão HTTP
A versão HTTP é a forma mais prática para obter a configuração do Veyon a ser implantada no computador do professor.

### Editando os valores padrão
- Faça uma cópia do arquivo `settings.py-example` e nomeie com `settings.py`;
- Edite o arquivo `settings.py` de acordo com as características de sua rede.

### Abrindo o servidor HTTP
O código abaixo é um exemplo de como abrir o servidor HTTP na porta 80 (troque a porta se necessário):

```bash
VEYON_HTTP_PORT=80 python3 http_server.py
```

### Lista de URLs disponíveis

- `/veyon` : Retorna a configuração da sala com base no IP que acessou o recurso (utilizado para o computador do professor)
- `/veyon/all`: Retorna a configuração de todas as salas configuradas

### Configurando o computador do professor
Você precisa criar um script que, de tempos em tempos, irá fazer a atualização da configuração do Veyon.

#### Em Windows
Use o agendador de tarefas para executar como administrador o seguinte script Powershell:

```powershell
iwr http://meu-servidor/veyon -OutFile C:\WINDOWS\Temp\veyon.json
& "C:\Program Files\Veyon\veyon-cli.exe" config import C:\WINDOWS\Temp\veyon.json
Restart-Service -Name VeyonService
```

#### Em Linux
Use o cron como root para executar o seguinte script bash:
```bash
VEYON_CONFIG_FILE="/tmp/.config.json"
wget "http://meu-servidor/veyon" -O $VEYON_CONFIG_FILE -q
veyon-cli config import $VEYON_CONFIG_FILE
systemctl restart veyon
```

## Uso da versão CLI

O script pode ser executado da seguinte forma:

```bash
python3 dhcp_to_veyon.py -f "<path_to_dhcpd.leases>" -n "<network1>" -n "<network2>" -r "<room1>" -r "<room2>" [-a "<ip_address>"] [--all]
```

### Parâmetros

- `-f <file_path>`: Caminho para o arquivo de leases DHCP ou URL contendo os dados de leases.
- `-n <network>`: Endereço de rede em formato CIDR (exemplo: `192.168.1.0/24`). Pode ser passado múltiplas vezes para especificar várias redes.
- `-r <room>`: Nome da sala ou grupo de máquinas. Pode ser passado múltiplas vezes para associar várias redes a diferentes salas.
- `-a <ip_address>`: Filtro para um IP específico. Se fornecido, o script retornará somente a configuração da sala onde o IP está presente.
- `--all`: Se fornecido, incluirá todas as salas, mesmo se o IP filtrado não pertencer a nenhuma rede especificada.

### Exemplos de uso 

1. **Conversão simples de DHCP para JSON do Veyon**:

```bash
python3 dhcp_to_veyon.py -f "dhcpd.leases" -n "10.1.2.0/24" -n "10.1.3.0/24" -r "Sala 2" -r "Sala 3"
```

Isso gerará um arquivo JSON com as configurações para as redes 10.1.2.0/24 e 10.1.3.0/24, associadas às salas "Sala 2" e "Sala 3".

2. **Filtragem por IP (retorna a sala com o IP fornecido)**:

```bash
python3 dhcp_to_veyon.py -f "dhcpd.leases" -n "10.1.2.0/24" -n "10.1.3.0/24" -r "Sala 2" -r "Sala 3" -a "10.1.2.200"
```

Isso retornará somente as máquinas da "Sala 2", excluindo qualquer máquina associada a outras redes ou salas.

3. **Quando o IP fornecido não pertence a nenhuma rede e --all não é fornecido**:

```bash
python3 dhcp_to_veyon.py -f "dhcpd.leases" -n "10.1.2.0/24" -n "10.1.3.0/24" -r "Sala 2" -r "Sala 3" -a "10.1.4.200"
```

Isso resultará em uma configuração vazia com a estrutura do Veyon e um JsonStoreArray vazio.

4. **Com a opção --all, incluirá todas as salas, mesmo se o IP não for encontrado em nenhuma rede**:
```bash
python3 dhcp_to_veyon.py -f "dhcpd.leases" -n "10.1.2.0/24" -n "10.1.3.0/24" -r "Sala 2" -r "Sala 3" -a "10.1.4.200" --all
```
Isso retornará todas as salas, incluindo "Sala 2" e "Sala 3", mesmo que o IP 10.1.4.200 não pertença a nenhuma rede.




