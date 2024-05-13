# Usar uma imagem base oficial do Python
FROM python:3.8-slim

# Define o diretório de trabalho no contêiner
WORKDIR /app

# Copia os arquivos necessários para o diretório de trabalho
COPY requirements.txt ./

# Instala as bibliotecas necessárias
RUN pip install --no-cache-dir -r requirements.txt

# Instalação de certificados, se necessário (descomente e ajuste conforme necessário)
# RUN apt-get update && apt-get install -y \
#     ca-certificates \
#     && update-ca-certificates

# Copia o restante do código fonte para o contêiner
COPY . .

# Expõe a porta 8050 para acesso ao Dash
EXPOSE 8050

# Comando para rodar a aplicação
CMD ["python", "app.py"]