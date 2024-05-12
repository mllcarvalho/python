from flask import Flask
from dash import dash_table, html, dcc, Input, Output, callback, dash, ctx
from flask_caching import Cache
import boto3
import pandas as pd
import datetime

# Setup do cliente AWS e do servidor Flask
elbv2_client = boto3.client('elbv2')
ecs_client = boto3.client('ecs')
dynamodb_client = boto3.client('dynamodb')
rds_client = boto3.client('rds')
cloudwatch_client = boto3.client('cloudwatch')
server = Flask(__name__)
app = dash.Dash(__name__, server=server, url_base_pathname='/')

# Configuração do Cache
cache = Cache(app.server, config={
    'CACHE_TYPE': 'filesystem',
    'CACHE_DIR': 'cache-directory',
    'CACHE_DEFAULT_TIMEOUT': 86400  # 24 horas
})

@app.callback(
    Output('cache-status', 'children'),
    Input('clear-cache-button', 'n_clicks')
)
def clear_cache(n_clicks):
    if n_clicks and n_clicks > 0:
        cache.clear()
        return "Cache cleared successfully!"
    return ""

@cache.memoize(timeout=86400)  # Cache a função por um dia
def fetch_ecs_data():
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
                    
                    
                    cpu_usage = get_cloudwatch_metric_average(cluster_name, service['serviceName'], 'CPUUtilization')
                    memory_usage = get_cloudwatch_metric_average(cluster_name, service['serviceName'], 'MemoryUtilization')
                    
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
def get_cloudwatch_metric_average(cluster_name, service_name, metric_name):
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

def fetch_dynamodb_data():
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

def fetch_rds_data():
    db_instances = rds_client.describe_db_instances()['DBInstances']
    data = []
    for instance in db_instances:
        db_identifier = instance['DBInstanceIdentifier']
        cpu_usage = get_cpu_usage(db_identifier)
        size = instance['DBInstanceClass']
        multi_az = instance['MultiAZ']
        data.append({
            'DB Identifier': db_identifier,
            'Status': instance['DBInstanceStatus'],
            'Engine': instance['Engine'],
            'Size': size,
            'CPU Usage': f"{cpu_usage}%",
            'Multi AZ': 'True' if multi_az else 'False'
        })
    return pd.DataFrame(data)

@cache.memoize(timeout=86400)  # Cache a função por um dia
def get_cpu_usage(db_instance_identifier):
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

def fetch_load_balancers():
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

app.layout = html.Div([
    html.H1('AWS Services Dashboard'),
    html.Button('Clear Cache', id='clear-cache-button'),
    html.Div(id='cache-status', style={'margin-bottom': '10px', 'display': 'block', 'color': 'green', 'font-weight': 'bold', 'font-size': '16px', 'margin-top': '10px'}),
    dcc.Tabs(id="tabs", children=[
        dcc.Tab(label='ECS Services', children=[
            dash_table.DataTable(
                id='ecs-table',
                columns=[{'name': i, 'id': i} for i in fetch_ecs_data().columns],
                data=fetch_ecs_data().to_dict('records'),
                filter_action='native',  # Permite filtragem
                sort_action='native',  # Permite ordenação
                style_cell={'textAlign': 'left', 'padding': '5px'},
                style_data_conditional=[
                    {'if': {'column_id': 'Capacity Provider', 'filter_query': '{Capacity Provider} eq "FARGATE" || {Capacity Provider} eq "N/A"'},
                     'backgroundColor': '#FFCCCC'}
                ]
            )
        ]),
        dcc.Tab(label='DynamoDB Tables', children=[
            dash_table.DataTable(
                id='dynamodb-table',
                columns=[{'name': i, 'id': i} for i in fetch_dynamodb_data().columns],
                data=fetch_dynamodb_data().to_dict('records'),
                filter_action='native',
                sort_action='native',
                style_cell={'textAlign': 'left', 'padding': '5px'}
            )
        ]),
        dcc.Tab(label='RDS Instances', children=[
            dash_table.DataTable(
                id='rds-table',
                columns=[{'name': i, 'id': i} for i in fetch_rds_data().columns],
                data=fetch_rds_data().to_dict('records'),
                filter_action='native',
                sort_action='native',
                style_cell={'textAlign': 'left', 'padding': '5px'},
                style_data_conditional=[
                    {'if': {'column_id': 'Size', 'filter_query': '{Size} contains "xlarge"'},
                     'backgroundColor': '#FFCCCC'},
                    {'if': {'column_id': 'Multi AZ', 'filter_query': '{Multi AZ} eq "True"'},
                     'backgroundColor': '#FFCCCC'}
                ]
            )
        ]),
        dcc.Tab(label='ELBs', children=[
            dash_table.DataTable(
                id='load-balancers-table',
                columns=[{'name': i, 'id': i} for i in fetch_load_balancers().columns],
                data=fetch_load_balancers().to_dict('records'),
                filter_action='native',
                sort_action='native',
                style_cell={'textAlign': 'left', 'padding': '5px'},
                style_data_conditional=[
                    {'if': {'column_id': 'Listeners', 'filter_query': '{Listeners} eq 0'},
                    'backgroundColor': '#FFCCCC'}
                ]
            )
        ]),
    ])
])

if __name__ == '__main__':
    app.run_server(debug=True)
