import logging
import azure.functions as func
import os
import requests
import json
from azure.storage.blob import BlobServiceClient, generate_blob_sas,BlobSasPermissions
from azure.storage.blob import BlobClient

def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    name = req.params.get('name')
    if not name:
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            name = req_body.get('name')


    null = ""
    schema = req_body
    #logging.info(schema)
    

    logging.info("Schema Data")
    logging.info(req_body)
    logging.info(name)

    
    # Extract data from Loganalytics API
    
    ## Log Analytics workspace parameters
    
    workspace_id = '22dfc2ac-69b2-4625-b64e-b33b00633811' 
    client_id = '16cb53c2-4ba2-41d0-9067-c70109a222b5' 
    client_secret = 'Jdi8Q~FiJHlbsLN8jO~jHVRgZTRg4yhx_OIqzc59' 
    tenant_id = '93f33571-550f-43cf-b09f-cd331338d086'  
    resource = 'https://api.loganalytics.io'
    
    account_key= 'd/0RHq4Mchnf4PusVapI0UOsPx7BRQkf8Pynr+iizz6h3ZKhCHrc/YGgyL+HmtXh8P3Ej7gCTcVz+ASti6cb+w==' #"HXNF39XT8dv7xfiuZhoeyiUB89o1fWKvPIle1XRVYxu9QyMk/8kSHNDMwosaezL0xCSu2euaJLlO+AStGay0vw=="
    
    """
    workspace_id = '8d314d7e-750c-43ec-9d21-b7a5fdbd25b4'
    client_id = 'cb84680a-dc5e-4967-97c6-6f5a4eca3020'
    client_secret = 'wti8Q~gCaXDb2PguqRiLcmiwfe-mlv7aJyLyvcWi'
    resource = 'https://api.loganalytics.io'
    tenant_id = '7b349f28-0155-4b2a-b3da-fd7fa44f092c'
    account_key= "HXNF39XT8dv7xfiuZhoeyiUB89o1fWKvPIle1XRVYxu9QyMk/8kSHNDMwosaezL0xCSu2euaJLlO+AStGay0vw=="
    """

    # Obtain an access token using client credentials
    token_url = f'https://login.microsoftonline.com/{tenant_id}/oauth2/token'
    token_data = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
        'resource': resource
    }
    token_response = requests.post(token_url, data=token_data)
    access_token = token_response.json().get('access_token')

    logging.info("token_response")
    logging.info(token_response)

    logging.info("access_token")
    logging.info(access_token)
    
    # Query parameters
    query = ""

    # API endpoint for querying Log Analytics data
    #query_url = f'https://api.loganalytics.io/v1/workspaces/8d314d7e-750c-43ec-9d21-b7a5fdbd25b4/query?query=AmlRunStatusChangedEvent%0A%7C%20where%20Status%20%3D%3D%20%27Failed%27%0A%7C%20join%20kind%3Dleftouter%20%28AmlComputeJobEvent%0A%20%20%20%20%7C%20where%20EventType%20%3D%3D%20%27JobFailed%27%0A%20%20%20%20%7C%20project%20JobName%2C%20ExperimentName%29%0A%20%20%20%20on%20%24left.RunId%20%3D%3D%20%24right.JobName%0A%7C%20extend%20joburl%20%3D%20strcat%28%27https%3A%2F%2Fml.azure.com%2Fruns%2F%27%2C%20RunId%2C%20%27%3Fwsid%3D%27%2C%20_ResourceId%29%0A%7C%20extend%20ResourceGroup%20%3D%20tostring%28tostring%28split%28_ResourceId%2C%20%27%2F%27%29%5B-1%5D%29%29%0A%7C%20extend%20Resource%20%3D%20tostring%28split%28split%28_ResourceId%2C%20%27%2F%27%29%5B8%5D%2C%20%27%2F%27%29%5B0%5D%29%0A%7C%20project%0A%20%20%20%20category%20%3D%20%27Application%27%2C%0A%20%20%20%20subcategory%20%3D%20%27%20Incident%20Break%20Fix%27%2C%0A%20%20%20%20contact_type%20%3D%20%27Event%27%2C%0A%20%20%20%20Application%3D%27%27%2C%0A%20%20%20%20Resource%2C%0A%20%20%20%20ResourceGroup%2C%0A%20%20%20%20dxcManaged%3D%27True%27%2C%0A%20%20%20%20dxcMonitored%3D%27True%27%2C%0A%20%20%20%20pipelineName%3D%27NA%27%2C%0A%20%20%20%20Status%2C%0A%20%20%20%20TimeGenerated%2C%0A%20%20%20%20SubscriptionId%3D_SubscriptionId%2C%0A%20%20%20%20Category%20%3D%20%27JobRuns%27%2C%0A%20%20%20%20Level%2C%0A%20%20%20%20OperationName%2C%0A%20%20%20%20Error_Message%20%3D%20Message%2C%0A%20%20%20%20ResourceId%3D_ResourceId%2C%0A%20%20%20%20AppSupportTeam%20%3D%20%27DXC_Application_Analytics%27%2C%0A%20%20%20%20AppOwner%20%3D%20%27Durgesh%20Kulkarni%27%2C%0A%20%20%20%20Environment%20%3D%27test%27%2C%0A%20%20%20%20StorageAccount%20%3D%20%22dxcmlsaforfnb%22%2C%0A%20%20%20%20RunId%0A%7C%20project-keep%0A%20%20%20%20category%2C%0A%20%20%20%20subcategory%2C%0A%20%20%20%20contact_type%2C%0A%20%20%20%20Application%2C%0A%20%20%20%20Resource%2C%0A%20%20%20%20ResourceGroup%2C%0A%20%20%20%20dxcManaged%2C%0A%20%20%20%20dxcMonitored%2C%0A%20%20%20%20pipelineName%2C%0A%20%20%20%20Status%2C%0A%20%20%20%20TimeGenerated%2C%0A%20%20%20%20SubscriptionId%2C%0A%20%20%20%20Category%2C%0A%20%20%20%20Level%2C%0A%20%20%20%20OperationName%2C%0A%20%20%20%20Error_Message%2C%0A%20%20%20%20ResourceId%2C%0A%20%20%20%20AppSupportTeam%2C%0A%20%20%20%20AppOwner%2C%0A%20%20%20%20Environment%2C%0A%20%20%20%20StorageAccount%2C%0A%20%20%20%20RunId&timespan=2023-08-08T01%3a31%3a11.0000000Z%2f2023-08-08T01%3a36%3a11.0000000Z'
    #query_url=f'https://portal.azure.com/#@93f33571-550f-43cf-b09f-cd331338d086/blade/Microsoft_Azure_Monitoring_Logs/LogsBlade/source/Alerts.EmailLinks/scope/%7B%22resources%22%3A%5B%7B%22resourceId%22%3A%22%2Fsubscriptions%2F7bc1bffc-b042-4756-9608-833445452f14%2Fresourcegroups%2Fcampbell%2Fproviders%2Fmicrosoft.machinelearningservices%2Fworkspaces%2Fwp-dxc-sandbox-dev-ml%22%7D%5D%7D/q/eJydU8Fu2zAMvRfoP%2BhQQAngxtttGGAMWZYW2dYWaHMYMASBYnOJGlsSKClJh3z8aFtK3SY9dD6Jj%2BQTxfc8rMp7rx6ccN6OVkItoRhvQLnzszTds%2B0KEFibZVnG%2BJWQJRScnZ%2Ft2aOWiq2lKrIS%2FjjtHSDrDatypCtDwXe9CEyMvme2Bpw%2BGWgIqSpwtnV7ZlA%2FQu4YZW5FBQkb7wygrKirjvttnVbsor52QNNPiprqAuVy5QahrR4Qdg5UQXMuPJYsY9ZhLlyPr5wz9nOaVuVA%2FPUIg1xXKXplU56whi9h%2FMvWyiIjYH4PVnvMYVL0O6wRvUbtDZE7TfRSLXuHgzWldL1OO7GmvP%2F78uOsf4qpS9L2vsXwaRYOH2YNUVhZuxl6Iiw1PhEdHxpiIEBqxZM2bf2iW8EmKpcF7ZZ9RRBrdiV3sTLXyonczV2jFeONcDHZYc54BOOgr8JmRQErdvmNUIJslvEpeuAdXCvpNL7OGGmglApqVTN%2BO4x468qEtdGUDHINCpDeVsQKv7A5SlMPOSmy%2Bcs4IU8eV4XWUWdF5CgyhY33%2FoQNlOF8R85sdtA4tcXGiBrnN2AtvZL6wympc%2FS9XE09Vlfew3IfvDEa3RREVc%2Fw7ddo3ln5fKhE%2BeRkfpiKkndben5T7HEJdsV%2B%2BHItUMlYM1YbiVrVfxLLuAN7ULMxfcdJl2sAE4aJbjn2zwmfHLvjf6yRHHsiQF0zBOi9PghgVDiE71L1LS1P6xcYokKR8FmMgDQi%2FAM%3D/prettify/1/timespan/2023-09-06T17%3a47%3a01.0000000Z%2f2023-09-06T17%3a52%3a01.0000000Z'
    query_url = schema['data']['alertContext']['condition']['allOf'][0]['linkToFilteredSearchResultsAPI']
    
    logging.info("query_url")
    logging.info(query_url)
    
    headers = {
    'Authorization': f'Bearer {access_token}',
    'Content-Type': 'application/json'
    }
    # query_data = {    'query': query    }

    # Make the query request
    #response = requests.get(query_url, headers=headers, data=json.dumps(query_data))
    response = requests.get(query_url, headers=headers)
    logging.info("Response - API Data extraction")
    logging.info(response)
    logging.info(response.content)


    if response.status_code == 200:
        query_result = response.json()
        #print(json.dumps(query_result, indent=2))
    else:
        print(f"Error: {response.status_code} - {response.text}")

    logging.info("API Result")
    logging.info(query_result)
    alert_result = query_result['tables'][0]['rows'][0]

    print("API data extracted!")

    columnnames=['category',
    'subcategory',
    'contact_type',
    'Application',
    'Resource',
    'ResourceGroup',
    'dxcManaged',
    'dxcMonitored',
    'pipelineName',
    'Status', 
    'TimeGenerated',
    'SubscriptionId',
    'Category',
    'Level',
    'OperationName',
    'Error_Message',       
    'ResourceId', 
    'AppSupportTeam',
    'AppOwner',
    'Environment',
    'RunId']

    ##########################################################################


    # Extract Error Message from Machine learning log file

    from azure.storage.blob import BlobClient

    blob = BlobClient(account_url="https://"+alert_result[-2]+".blob.core.windows.net",
                container_name="azureml",
                blob_name="ExperimentRun/dcid."+alert_result[-1]+"/user_logs/std_log.txt",
                
                credential=account_key)

    with open("example.txt", "wb") as f:
        data = blob.download_blob()
    data.readinto(f)

    path_to_file=r"example.txt"
    with open(path_to_file) as f:
        contents = f.readlines()
    f.close()

    error_contents = []
    for i in range(len(contents)):
        if "Error" in contents[i]:
            error_contents.append(contents[i])


    columnvalues=[error_contents[0]]+alert_result
    columnnames=["error.logfile"]+columnnames

    description_content = dict(zip(columnnames, columnvalues))
    
    print("ML Log  data extracted!")

        
    ##########################################################################
    
    # Create Servicenow ticket 
    
    servicenow_url = 'https://campbellsouptest.service-now.com/api/now/table/incident'
    servicenow_user = 'azure.ml.monitoring'
    servicenow_password = 'a$8DH6Yl,dRBgAdU7Bw8M{r_QH51D83,uRr[)J;F'
    payload = {
            #"short_description": schema['data']['essentials']['alertRule'],
            #"description": description_content
            "short_description": schema['data']['essentials']['alertRule'],
            "description": schema
        }

    headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

    response = requests.post(servicenow_url, json=payload, auth=(servicenow_user, servicenow_password), headers=headers)

    if response.status_code == 201:
        return func.HttpResponse("ServiceNow ticket created successfully.", status_code=200)
    else:
        return func.HttpResponse(f"Failed to create ServiceNow ticket. Status code: {response.status_code}", status_code=500)
    
    
    
    """
    
    if name:
        return func.HttpResponse(f"Hello, {name}. This HTTP triggered function executed successfully.")
    else:
        return func.HttpResponse(
             "This HTTP triggered function executed successfully. Pass a name in the query string or in the request body for a personalized response.",
             status_code=200
        )
    """