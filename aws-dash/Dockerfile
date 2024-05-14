# Usar uma imagem base oficial do Python
FROM python:3.8-slim

# Define o diretório de trabalho no contêiner
WORKDIR /app

# Copia o restante do código fonte para o contêiner
COPY . .

# Expõe a porta 8050 para acesso ao Dash
EXPOSE 8050

# Comando para rodar a aplicação
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.8050", "aws:server"]