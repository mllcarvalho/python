# Usar uma imagem base oficial do Python
FROM itau-ha4-docker.artifactory.prod.aws.cloud.ihf/itau-corp-itau-ha4-container-goldenimagepython:v0.1.0-a42ad38

# Define o diretório de trabalho no contêiner
WORKDIR /app

# Copia o restante do código fonte para o contêiner
COPY . .

# Expõe a porta 8050 para acesso ao Dash
EXPOSE 8050

# Comando para rodar a aplicação
CMD ["gunicorn", "aws:server", "-c", "gunicorn_config.py"]