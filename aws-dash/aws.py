from flask import Flask
from dash import dash_table, html, dcc, Input, Output, callback, dash, ctx, State
from flask_caching import Cache
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
def create_aws_session(access_key, secret_key, session_token):
    return boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token
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
        html.H1('AWS Services Dashboard'),
        html.Button('Clear Cache', id='clear-cache-button'),
        html.Div(id='cache-status', style={'margin-bottom': '10px', 'display': 'block', 'color': 'green', 'font-weight': 'bold', 'font-size': '16px', 'margin-top': '10px'}),
    ], style={'textAlign': 'center'}),
    html.Div([
        dcc.Input(id='aws-access-key', type='text', placeholder='AWS Access Key', style={'marginRight': '5px'}),
        dcc.Input(id='aws-secret-key', type='password', placeholder='AWS Secret Key', style={'marginRight': '5px'}),
        dcc.Input(id='aws-session-token', type='password', placeholder='AWS Session Token', style={'marginRight': '5px'}),
        html.Button('Refresh', id='refresh-button', n_clicks=0)
    ], style={'position': 'absolute', 'top': '10px', 'right': '10px', 'zIndex': '1000'}),
    dcc.Tabs(id="tabs", children=[
        dcc.Tab(label='ECS Services', children=[html.Div(id='ecs-dashboard')]),
        dcc.Tab(label='DynamoDB Tables', children=[html.Div(id='dynamodb-dashboard')]),
        dcc.Tab(label='RDS Instances', children=[html.Div(id='rds-dashboard')]),
        dcc.Tab(label='Load Balancers', children=[html.Div(id='load-balancer-dashboard')]),
        dcc.Tab(label='API Gateway', children=[html.Div(id='api-gateway-dashboard')]),
    ])
])

@app.callback(
    [Output('ecs-dashboard', 'children'),
     Output('dynamodb-dashboard', 'children'),
     Output('rds-dashboard', 'children'),
     Output('load-balancer-dashboard', 'children'),
     Output('api-gateway-dashboard', 'children'),],
    Input('refresh-button', 'n_clicks'),
    [State('aws-access-key', 'value'), State('aws-secret-key', 'value'), State('aws-session-token', 'value')]
)
def update_dashboards(n_clicks, access_key, secret_key, session_token):
    if n_clicks > 0:
        session = create_aws_session(access_key, secret_key, session_token)
        ecs_client = session.client('ecs')
        dynamodb_client = session.client('dynamodb')
        rds_client = session.client('rds')
        elbv2_client = session.client('elbv2')
        cloudwatch_client = session.client('cloudwatch')
        apigateway_client = session.client('apigateway')
        s3_client = session.client('s3')

        ecs_data = fetch_ecs_data(ecs_client, cloudwatch_client)
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
            style_cell={'textAlign': 'left', 'padding': '5px'}
        )

        return ecs_table, dynamodb_table, rds_table, load_balancer_table, api_gateway_table
    return html.Div(), html.Div(), html.Div(), html.Div(), html.Div() # Return empty divs if not refreshed yet

def fetch_ecs_data(ecs_client, cloudwatch_client):
    data = []
    cluster_paginator = ecs_client.get_paginator('list_clusters')
    for cluster_page in cluster_paginator.paginate():
        for cluster_arn in cluster_page['clusterArns']:
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
                    
                    cpu_usage = get_cloudwatch_metric_average(cloudwatch_client, cluster_name, service['serviceName'], 'CPUUtilization')
                    memory_usage = get_cloudwatch_metric_average(cloudwatch_client, cluster_name, service['serviceName'], 'MemoryUtilization')
                    
                    data.append({
                        'Cluster Name': cluster_name,
                        'Service Name': service['serviceName'],
                        'Task Count': service['desiredCount'],
                        'Capacity Provider': service.get('capacityProviderStrategy', [{'capacityProvider': 'N/A'}])[0]['capacityProvider'],
                        'vCPU': task_cpu,
                        'Memory': task_memory,
                        'Avg CPU Usage (%)': cpu_usage,
                        'Avg Memory Usage (%)': memory_usage,    
                    })
    df = pd.DataFrame(data)
    # Ordenando o DataFrame
    df_sorted = df.sort_values(by=['Cluster Name', 'Service Name'], ascending=[True, True])
    return df_sorted

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
    for page in paginator.paginate():
        for table_name in page['TableNames']:
            table_info = dynamodb_client.describe_table(TableName=table_name)['Table']
            billing_mode = table_info.get('BillingModeSummary', {}).get('BillingMode', 'PROVISIONED')
            table_data.append({
                'Table Name': table_name,
                'Status': table_info['TableStatus'],
                'Billing Mode': billing_mode,
                'Read Capacity Units': table_info['ProvisionedThroughput']['ReadCapacityUnits'],
                'Write Capacity Units': table_info['ProvisionedThroughput']['WriteCapacityUnits'], 
            })
    return pd.DataFrame(table_data)

def fetch_rds_data(rds_client, cloudwatch_client):
    db_instances = rds_client.describe_db_instances()['DBInstances']
    data = []
    for instance in db_instances:
        db_identifier = instance['DBInstanceIdentifier']
        read_replica_count = len(instance.get('ReadReplicaDBInstanceIdentifiers', []))
        has_read_replica = "True" if read_replica_count > 0 else "False"
        cpu_usage = get_cpu_usage(cloudwatch_client, db_identifier)
        size = instance['DBInstanceClass']
        multi_az = instance['MultiAZ']
        data.append({
            'DB Identifier': db_identifier,
            'Status': instance['DBInstanceStatus'],
            'Engine': instance['Engine'],
            'Read Replica': has_read_replica,
            'Size': size,
            'CPU Usage': f"{cpu_usage}%",
            'Multi AZ': 'True' if multi_az else 'False'
        })
    return pd.DataFrame(data)

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
    data = []
    response = elbv2_client.describe_load_balancers()
    load_balancers = response['LoadBalancers']
    
    for lb in load_balancers:
        listeners_response = elbv2_client.describe_listeners(LoadBalancerArn=lb['LoadBalancerArn'])
        listener_count = len(listeners_response['Listeners'])
        
        data.append({
            'Load Balancer Name': lb['LoadBalancerName'],
            'Load Balancer ARN': lb['LoadBalancerArn'],
            'Type': lb['Type'],
            'Listeners': listener_count
        })
    df = pd.DataFrame(data)
    # Ordenando o DataFrame
    df_sorted = df.sort_values(by=['Load Balancer Name'], ascending=[True])
    return df_sorted

# Definindo a função para recuperar dados dos API Gateways
def fetch_api_gateway_data(apigateway_client):
    # Recuperar todos os gateways
    response = apigateway_client.get_rest_apis()
    items = response['items']
    
    data = []
    for item in items:
        # Detalhes do log e X-Ray
        try:
            stage_response = apigateway_client.get_stages(restApiId=item['id'])
            for stage in stage_response['item']:
                logs = stage.get('methodSettings', {}).get('*', {}).get('loggingLevel', 'OFF')
                xray = stage.get('methodSettings', {}).get('*', {}).get('dataTraceEnabled', False)
                data.append({
                    'API Name': item['name'],
                    'API ID': item['id'],
                    'Stage Name': stage['stageName'],
                    'Logging Level': logs,
                    'X-Ray Enabled': xray
                })
        except Exception as e:
            print(f"Error fetching stages for API {item['name']}: {str(e)}")
    
    df = pd.DataFrame(data)
    df_sorted = df.sort_values(by=['API Name'], ascending=[True])
    return df_sorted

if __name__ == '__main__':
    app.run_server(debug=True)