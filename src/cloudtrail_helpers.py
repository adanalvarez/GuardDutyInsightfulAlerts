import boto3
from botocore.exceptions import ClientError
import logging
from datetime import datetime, timedelta
import time
import html
from utils import get_nested_value


def get_cloudtrail_information_section(event, event_data_store_arn, ip_address_v4):
    """Retrieves CloudTrail information based on the event data store ARN, access key ID, and IP address."""
    if not event_data_store_arn:
        logging.info("No event data store configured.")
        return ""
    event_data_store_region = event_data_store_arn.split(":")[3]
    accesskeyid_path = ["detail", "resource", "accessKeyDetails", "accessKeyId"]
    accesskeyid = get_nested_value(event, accesskeyid_path)
    event_data_store_id = check_data_storage_existence(
        event_data_store_arn, event_data_store_region
    )
    if not event_data_store_id:
        logging.error("Event Data Store does not exist or could not be verified.")
        return ""

    queries = get_queries(accesskeyid, ip_address_v4, event_data_store_id)
    if not queries:
        logging.info("No queries to execute.")
        return ""

    query_results = execute_queries(
        queries, event_data_store_arn, event_data_store_region
    )
    if query_results is None:
        logging.error("Failed to execute queries or no results returned.")
        return ""

    query_results_tables = format_query_results(query_results)
    return format_cloudtrail_information(query_results_tables)


def get_queries(access_key_id, ip_address, event_data_store_id):
    """Generates SQL queries for CloudTrail data based on the given access key ID and IP address."""
    # Calculate the date 7 days ago
    fifteen_days_ago = datetime.now() - timedelta(days=7)
    formatted_date = fifteen_days_ago.strftime("%Y-%m-%d %H:%M:%S")

    queries = {}
    if access_key_id:
        queries[
            "IPs used from the same user"
        ] = f"""
            SELECT DISTINCT sourceIpAddress
            FROM {event_data_store_id}
            WHERE userIdentity.accessKeyId = '{access_key_id}'
                AND eventTime > '{formatted_date}'
            ORDER BY sourceIpAddress;
        """

    if ip_address:
        queries[
            "User identities that have conected from the same IP"
        ] = f"""
            SELECT DISTINCT userIdentity.arn
            FROM {event_data_store_id}
            WHERE userIdentity.arn IS NOT NULL
                AND sourceIpAddress = '{ip_address}'
                AND eventTime > '{formatted_date}'
            ORDER BY userIdentity.arn;
        """

    return queries


def execute_queries(queries, event_data_store_arn, event_data_store_region):
    """Executes a set of queries against the given Event Data Store and retrieves their results."""
    query_ids = {
        query_data_storage(queries[query], event_data_store_region): query
        for query in queries
    }
    results = {}

    while query_ids:
        for query_id, query in list(query_ids.items()):
            try:
                if not is_query_still_running(
                    query_id, event_data_store_arn, event_data_store_region
                ):
                    query_result = get_query_results(
                        query_id, event_data_store_arn, event_data_store_region
                    )
                    if query_result:
                        results[query] = query_result
                    query_ids.pop(query_id)
            except ClientError as e:
                logging.error(
                    f"Error fetching results for {query_id}: {e.response['Error']['Message']}"
                )
                query_ids.pop(query_id)  # Remove the failed query ID

        time.sleep(5)  # Wait before checking the status again

    return results


def format_query_results(query_results):
    """Formats the results of multiple queries into HTML tables."""
    html_tables = ""
    for query_name, results in query_results.items():
        if results:
            html_tables += create_table_for_query(query_name, results)

    return html_tables


def create_table_for_query(query, results):
    """Creates an HTML table for a given query and its results."""
    table_rows = "".join(
        [
            f"<tr><td>{html.escape(str(list(result[0].values())[0]))}</td></tr>"
            for result in results
        ]
    )
    return f"<table><tr><th>{query}</th></tr>{table_rows}</table>"


def check_data_storage_existence(event_data_store_arn, event_data_store_region):
    """Checks if the specified AWS CloudTrail Event Data Store exists."""
    cloudtrail_client = boto3.client("cloudtrail", region_name=event_data_store_region)

    try:
        response = cloudtrail_client.get_event_data_store(
            EventDataStore=event_data_store_arn
        )
        arn = response["EventDataStoreArn"]
        data_store_id = arn.split("/")[-1]
        logging.info(f"CloudTrail Data Storage exists.")
        return data_store_id
    except ClientError as e:
        logging.error(f"Error getting Data Storage: {e.response['Error']['Message']}")
        return None


def query_data_storage(query, event_data_store_region):
    """Executes a query against AWS CloudTrail's data storage and returns the query ID."""
    client = boto3.client("cloudtrail", region_name=event_data_store_region)

    try:
        response = client.start_query(QueryStatement=query)
        logging.info(f"Query ID: {response['QueryId']}")
        return response.get("QueryId")
    except ClientError as e:
        logging.error(f"Error executing query: {e.response['Error']['Message']}")
        return None


def get_query_results(query_id, event_data_store_arn, event_data_store_region):
    """Retrieves the results of a query from an AWS CloudTrail Event Data Store."""
    client = boto3.client("cloudtrail", region_name=event_data_store_region)

    try:
        response = client.get_query_results(
            EventDataStore=event_data_store_arn, QueryId=query_id, MaxQueryResults=10
        )
        logging.info(
            f"Results for query with ID {query_id}: {response['QueryResultRows']}"
        )
        return response.get("QueryResultRows")
    except ClientError as e:
        logging.error(
            f"Error retrieving query results: {e.response['Error']['Message']}"
        )
        return None


def is_query_still_running(query_id, event_data_store_arn, event_data_store_region):
    """Checks if the specified query is still running in AWS CloudTrail's Event Data Store."""
    client = boto3.client("cloudtrail", region_name=event_data_store_region)

    try:
        response = client.get_query_results(
            EventDataStore=event_data_store_arn, QueryId=query_id, MaxQueryResults=10
        )
        state = response["QueryStatus"]
        logging.info(f"Status for query ID {query_id}: {state}")
        return state in ["QUEUED", "RUNNING"]
    except ClientError as e:
        logging.error(f"Error getting query state: {e.response['Error']['Message']}")
        return None


def format_cloudtrail_information(results):
    """Formats CloudTrail query results into an HTML section."""

    sections_html = f"""
        <div class="section">
            <div class="section-title">CloudTrail Information</div>
            {results}
        </div>
        """
    return sections_html
