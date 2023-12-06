import boto3
from botocore.exceptions import ClientError
import logging
import os


def generate_email_html(style, sections, guardduty_url):
    """Generates an HTML email template with GuardDuty information, IP information, and CloudTrail information."""
    combined_sections = "".join(sections)
    return f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>GuardDuty Alert</title>
            {style}
        </head>
        <body>
        <div class="container">
            <div class="header">GuardDuty Alert</div>
            {combined_sections}
            <center><a href="{guardduty_url}" target="_blank" class="go-to-finding-btn">Go to finding</a></center>
        </div>
        </body>
        </html>
    """


def send_email(html_content, severity, finding_title, source_email, destination_email):
    """Sends an email using AWS SES."""
    ses_client = boto3.client("ses")

    if not source_email or not destination_email:
        logging.error(
            "Source and destination emails are required. Please set them as environment variables."
        )
        return

    subject = f"[AWS GuardDuty Alert][Severity: {severity}] {finding_title}"

    try:
        response = ses_client.send_email(
            Source=source_email,
            Destination={"ToAddresses": [destination_email]},
            Message={
                "Subject": {"Data": subject},
                "Body": {"Html": {"Data": html_content}},
            },
        )
        logging.info(f"Email sent successfully: {response['MessageId']}")
    except ClientError as e:
        logging.error(f"Error sending email: {e.response['Error']['Message']}")
