# lambda_function.py
import logging
import os
from styles import generate_style
from guardduty_helpers import generate_guardduty_information_section, get_guardduty_url
from email_helpers import generate_email_html, send_email
from cloudtrail_helpers import get_cloudtrail_information_section
from ip_helpers import get_ip_information_section

# Configure logging
logging.basicConfig(level=logging.INFO)

def lambda_handler(event, context):
    # Environment variables and constants
    api_key = os.environ.get('VPNAPI_KEY')
    event_data_store_arn = os.environ.get('EVENT_DATA_STORE')
    source_email = os.environ.get('SOURCE_EMAIL')
    destination_email = os.environ.get('DESTINATION_EMAIL')

    # Generate HTML sections
    sections = []
    style = generate_style(event)
    guardduty_url = get_guardduty_url(event)

    guardduty_information = generate_guardduty_information_section(event)
    sections.append(guardduty_information)

    ip_information, ip_address_v4 = get_ip_information_section(event, api_key)
    sections.append(ip_information)

    cloudtrail_information = get_cloudtrail_information_section(
        event, event_data_store_arn, ip_address_v4)
    sections.append(cloudtrail_information)

    # Generate and send email
    email_html = generate_email_html(
        style,
        sections,
        guardduty_url)
    send_email(
        email_html,
        event['detail']['severity'],
        event['detail']['title'],
        source_email,
        destination_email)
