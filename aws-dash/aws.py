from flask import Flask
from dash import dash_table, html, dcc, Input, Output, callback, dash, ctx, State
from flask_caching import Cache
from concurrent.futures import ThreadPoolExecutor
import boto3
import pandas as pd
import datetime

server = Flask(__name__)
app = dash.Dash(__name__, server=server, url_base_pathname='/')

# Configuração do Cache
cache = Cache(app.server, config={
    'CACHE_TYPE': 'filesystem',
    'CACHE_DIR': 'cache-directory',
    'CACHE_DEFAULT_TIMEOUT': 86400  # 24 horas
})

# Função para criar clientes AWS com novas credenciais
def create_aws_session(credentials):
    return boto3.Session(
        aws_access_key_id=credentials['aws_access_key_id'],
        aws_secret_access_key=credentials['aws_secret_access_key'],
        aws_session_token=credentials['aws_session_token']
    )

@app.callback(
    Output('cache-status', 'children'),
    Input('clear-cache-button', 'n_clicks')
)
def clear_cache(n_clicks):
    if n_clicks and n_clicks > 0:
        cache.clear()
        return "Cache cleared successfully!"
    return ""

# Layout principal
app.layout = html.Div([
    html.Div([
        html.Div([
            html.H1('AWS Services Dashboard', style={'display': 'inline-block'}),
            dcc.Input(id='account-id-display', type='text', placeholder='Account ID', style={'margin-left': '20px', 'border': 'none', 'color': 'blue', 'width': '200px', 'display': 'inline-block', 'font-weight': 'bold'}, readOnly=True),
        ], style={'width': '30%', 'display': 'inline-block', 'vertical-align': 'top'}),

        html.Div([
            dcc.Textarea(id='aws-creds-input', style={'width': '100%', 'height': '100px'}, placeholder="Enter AWS credentials in format:\naws_access_key_id=XXX\naws_secret_access_key=XXX\naws_session_token=XXX"),
            html.Button('Refresh', id='refresh-button', n_clicks=0, style={'margin-top': '5px'}),
        ], style={'width': '40%', 'display': 'inline-block', 'vertical-align': 'top'}),

        html.Div([
            html.Button('Clear Cache', id='clear-cache-button'),
            html.Div(id='cache-status', style={'color': 'green', 'font-weight': 'bold', 'margin-top': '5px'})
        ], style={'width': '30%', 'display': 'inline-block', 'text-align': 'right', 'vertical-align': 'top'}),
    ], style={'width': '100%', 'display': 'block', 'margin-bottom': '10px'}),

    dcc.Loading(
        id="loading-1",
        type="default",
        children=dcc.Tabs(id="tabs", children=[
            dcc.Tab(label='ECS Services', children=[html.Div(id='ecs-dashboard')]),
            dcc.Tab(label='DynamoDB Tables', children=[html.Div(id='dynamodb-dashboard')]),
            dcc.Tab(label='RDS Instances', children=[html.Div(id='rds-dashboard')]),
            dcc.Tab(label='Load Balancers', children=[html.Div(id='load-balancer-dashboard')]),
            dcc.Tab(label='API Gateway', children=[html.Div(id='api-gateway-dashboard')])
        ])
    )
])

@app.callback(
    [Output('ecs-dashboard', 'children'),
     Output('dynamodb-dashboard', 'children'),
     Output('rds-dashboard', 'children'),
     Output('load-balancer-dashboard', 'children'),
     Output('api-gateway-dashboard', 'children'),
     Output('account-id-display', 'value')],
    Input('refresh-button', 'n_clicks'),
    State('aws-creds-input', 'value')
)
def update_dashboards(n_clicks, creds_input):
    if n_clicks > 0 and creds_input:
        # Processa as credenciais a partir da entrada do usuário
        credentials = {}
        for line in creds_input.split('\n'):
            parts = line.split('=', 1)  # Divide apenas no primeiro '=' encontrado
            if len(parts) == 2:
                key, value = parts
                credentials[key.strip()] = value.strip()

        session = create_aws_session(credentials)
        sts_client = session.client('sts')
        account_id = sts_client.get_caller_identity().get('Account')

        ecs_client = session.client('ecs')
        dynamodb_client = session.client('dynamodb')
        rds_client = session.client('rds')
        elbv2_client = session.client('elbv2')
        cloudwatch_client = session.client('cloudwatch')
        apigateway_client = session.client('apigateway')

        ecs_data = fetch_ecs_data_concurrent(ecs_client, cloudwatch_client)
        dynamodb_data = fetch_dynamodb_data(dynamodb_client)
        rds_data = fetch_rds_data(rds_client, cloudwatch_client)
        elbv2_data = fetch_load_balancers(elbv2_client)
        api_data = fetch_api_gateway_data(apigateway_client)

        ecs_table = dash_table.DataTable(
            id='ecs-table',
            columns=[{'name': i, 'id': i} for i in ecs_data.columns],
            data=ecs_data.to_dict('records'),
            filter_action='native',  # Permite filtragem
            sort_action='native',  # Permite ordenação
            style_cell={'textAlign': 'left', 'padding': '5px'},
            style_data_conditional=[
                {'if': {'column_id': 'Capacity Provider', 'filter_query': '{Capacity Provider} eq "FARGATE" || {Capacity Provider} eq "N/A"'},
                 'backgroundColor': '#FFCCCC'}
            ]
        )

        dynamodb_table = dash_table.DataTable(
            id='dynamodb-table',
            columns=[{'name': i, 'id': i} for i in dynamodb_data.columns],
            data=dynamodb_data.to_dict('records'),
            filter_action='native',
            sort_action='native',
            style_cell={'textAlign': 'left', 'padding': '5px'}
        )

        rds_table = dash_table.DataTable(
            id='rds-table',
            columns=[{'name': i, 'id': i} for i in rds_data.columns],
            data=rds_data.to_dict('records'),
            filter_action='native',
            sort_action='native',
            style_cell={'textAlign': 'left', 'padding': '5px'},
            style_data_conditional=[
                {'if': {'column_id': 'Size', 'filter_query': '{Size} contains "xlarge"'},
                 'backgroundColor': '#FFCCCC'},
                {'if': {'column_id': 'Multi AZ', 'filter_query': '{Multi AZ} eq "True"'},
                 'backgroundColor': '#FFCCCC'},
                {'if': {'column_id': 'Has Read Replica', 'filter_query': '{Has Read Replica} eq "True"'},
                 'backgroundColor': '#FFCCCC'}
            ]
        )

        load_balancer_table = dash_table.DataTable(
            id='load-balancers-table',
            columns=[{'name': i, 'id': i} for i in elbv2_data.columns],
            data=elbv2_data.to_dict('records'),
            filter_action='native',
            sort_action='native',
            style_cell={'textAlign': 'left', 'padding': '5px'},
            style_data_conditional=[
                {'if': {'column_id': 'Listeners', 'filter_query': '{Listeners} eq 0'},
                'backgroundColor': '#FFCCCC'}
            ]
        )

        api_gateway_table = dash_table.DataTable(
            id='api-table',
            columns=[{'name': i, 'id': i} for i in api_data.columns],
            data=api_data.to_dict('records'),
            filter_action='native',
            sort_action='native',
            style_cell={'textAlign': 'left', 'padding': '5px'},
            style_data_conditional=[
                {'if': {'column_id': 'Logging Level', 'filter_query': '{Logging Level} != "OFF"'},
                'backgroundColor': '#FFCCCC'},
                {'if': {'column_id': 'X-Ray Enabled', 'filter_query': '{X-Ray Enabled} eq True'},
                'backgroundColor': '#FFCCCC'}
            ]
        )

        return [ecs_table, dynamodb_table, rds_table, load_balancer_table, api_gateway_table, account_id]
    # Se não clicar ou não tiver credenciais, retorna divs vazias e sem ID da conta
    return [html.Div()]*5 + [""]

def fetch_ecs_data_concurrent(ecs_client, cloudwatch_client):
    data = []
    cluster_paginator = ecs_client.get_paginator('list_clusters')
    cluster_list = [cluster_arn for page in cluster_paginator.paginate() for cluster_arn in page['clusterArns']]
    
    # Função para processar cada serviço
    def process_service(cluster_arn):
        cluster_name = cluster_arn.split('/')[-1]
        service_paginator = ecs_client.get_paginator('list_services')
        for service_page in service_paginator.paginate(cluster=cluster_arn):
            described_services = ecs_client.describe_services(
                cluster=cluster_arn, services=service_page['serviceArns']
            )['services']
            
            for service in described_services:
                task_def_arn = service['taskDefinition']
                task_def = ecs_client.describe_task_definition(taskDefinition=task_def_arn)
                task_cpu = task_def['taskDefinition'].get('cpu', 'N/A')  
                task_memory = task_def['taskDefinition'].get('memory', 'N/A')
                
                container_definitions = task_def['taskDefinition']['containerDefinitions']
                log_configuration = container_definitions[0].get('logConfiguration', {}) if container_definitions else {}
                log_driver = log_configuration.get('logDriver', 'None')
                
                cpu_usage = get_cloudwatch_metric_average(cloudwatch_client, cluster_name, service['serviceName'], 'CPUUtilization')
                memory_usage = get_cloudwatch_metric_average(cloudwatch_client, cluster_name, service['serviceName'], 'MemoryUtilization')
                
                data.append({
                    'Cluster Name': cluster_name,
                    'Service Name': service['serviceName'],
                    'Task Count': service['desiredCount'],
                    'Log Driver': log_driver,
                    'Capacity Provider': service.get('capacityProviderStrategy', [{'capacityProvider': 'N/A'}])[0]['capacityProvider'],
                    'vCPU': task_cpu,
                    'Memory': task_memory,
                    'Avg CPU Usage (%)': cpu_usage,
                    'Avg Memory Usage (%)': memory_usage,
                })

    # Uso de ThreadPool para processar cada cluster em paralelo
    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(process_service, cluster_list)

    df = pd.DataFrame(data)
    return df.sort_values(by=['Cluster Name', 'Service Name'], ascending=[True, True])


@cache.memoize(timeout=86400)  # Cache a função por um dia
def get_cloudwatch_metric_average(cloudwatch_client, cluster_name, service_name, metric_name):
    now = datetime.datetime.utcnow()
    response = cloudwatch_client.get_metric_statistics(
        Namespace='AWS/ECS',
        MetricName=metric_name,
        Dimensions=[
            {'Name': 'ClusterName', 'Value': cluster_name},
            {'Name': 'ServiceName', 'Value': service_name}
        ],
        StartTime=now - datetime.timedelta(minutes=10),
        EndTime=now,
        Period=300,  # Daily statistics
        Statistics=['Average']
    )
    return response['Datapoints'][-1]['Average'] if response['Datapoints'] else "No data"

def fetch_dynamodb_data(dynamodb_client):
    table_data = []
    paginator = dynamodb_client.get_paginator('list_tables')

    def describe_table(table_name):
        table_info = dynamodb_client.describe_table(TableName=table_name)['Table']
        return {
            'Table Name': table_name,
            'Status': table_info['TableStatus'],
            'Billing Mode': table_info.get('BillingModeSummary', {}).get('BillingMode', 'PROVISIONED'),
            'Read Capacity Units': table_info['ProvisionedThroughput']['ReadCapacityUnits'],
            'Write Capacity Units': table_info['ProvisionedThroughput']['WriteCapacityUnits']
        }

    # Recuperar todos os nomes de tabela primeiro
    table_names = [name for page in paginator.paginate() for name in page['TableNames']]
    
    # Usar ThreadPool para descrever cada tabela
    with ThreadPoolExecutor(max_workers=10) as executor:
        table_descriptions = list(executor.map(describe_table, table_names))

    return pd.DataFrame(table_descriptions)


def fetch_rds_data(rds_client, cloudwatch_client):
    def describe_instance(instance):
        db_identifier = instance['DBInstanceIdentifier']
        cpu_usage = get_cpu_usage(cloudwatch_client, db_identifier)
        return {
            'DB Identifier': db_identifier,
            'Status': instance['DBInstanceStatus'],
            'Engine': instance['Engine'],
            'Read Replica': "True" if len(instance.get('ReadReplicaDBInstanceIdentifiers', [])) > 0 else "False",
            'Size': instance['DBInstanceClass'],
            'CPU Usage': f"{cpu_usage}%",
            'Multi AZ': 'True' if instance['MultiAZ'] else 'False'
        }

    instances = rds_client.describe_db_instances()['DBInstances']
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        instance_data = list(executor.map(describe_instance, instances))

    return pd.DataFrame(instance_data)

@cache.memoize(timeout=86400)  # Cache a função por um dia
def get_cpu_usage(cloudwatch_client, db_instance_identifier):
    now = datetime.datetime.utcnow()
    stats = cloudwatch_client.get_metric_statistics(
        Namespace='AWS/RDS',
        MetricName='CPUUtilization',
        Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': db_instance_identifier}],
        StartTime=now - datetime.timedelta(minutes=10),
        EndTime=now,
        Period=300,
        Statistics=['Average']
    )
    return stats['Datapoints'][-1]['Average'] if stats['Datapoints'] else "No data"

def fetch_load_balancers(elbv2_client):
    def describe_load_balancer(lb):
        listeners_response = elbv2_client.describe_listeners(LoadBalancerArn=lb['LoadBalancerArn'])
        listener_count = len(listeners_response['Listeners'])
        return {
            'Load Balancer Name': lb['LoadBalancerName'],
            'Load Balancer ARN': lb['LoadBalancerArn'],
            'Type': lb['Type'],
            'Listeners': listener_count
        }

    load_balancers = elbv2_client.describe_load_balancers()['LoadBalancers']
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        lb_data = list(executor.map(describe_load_balancer, load_balancers))

    return pd.DataFrame(lb_data)

# Definindo a função para recuperar dados dos API Gateways
def fetch_api_gateway_data(apigateway_client):
    def get_api_details(api):
        try:
            stage_response = apigateway_client.get_stages(restApiId=api['id'])
            return [{
                'API Name': api['name'],
                'API ID': api['id'],
                'Stage Name': stage['stageName'],
                'Logging Level': stage.get('methodSettings', {}).get('*', {}).get('loggingLevel', 'OFF'),
                'X-Ray Enabled': stage.get('methodSettings', {}).get('*', {}).get('dataTraceEnabled', False)
            } for stage in stage_response['item']]
        except Exception as e:
            print(f"Error fetching stages for API {api['name']}: {str(e)}")
            return []

    paginator = apigateway_client.get_paginator('get_rest_apis')
    api_list = [api for page in paginator.paginate() for api in page['items']]
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        api_details = list(executor.map(get_api_details, api_list))
        # Flatten the list of lists
        api_details_flat = [item for sublist in api_details for item in sublist]

    return pd.DataFrame(api_details_flat)

if __name__ == '__main__':
    app.run_server(debug=True)