import html
from utils import get_nested_value
import logging


def generate_guardduty_information_section(finding):
    """Generates HTML section with GuardDuty information."""

    def add_section(label, *keys):
        """Adds a section to the HTML output if the specified keys exist in the finding."""
        value = finding["detail"]
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                logging.info(f"Key not found: {key}")
                return

        safe_value = html.escape(str(value))
        if "severity" in keys:
            sections.append(
                f"<div class='severity'>{label}: <span>{safe_value}</span></div>"
            )
        else:
            sections.append(
                f"<div>{label}: <span class='value'>{safe_value}</span></div>"
            )

    sections = []

    # Standard sections
    add_section("Severity", "severity")
    add_section("Title", "title")
    add_section("Description", "description")
    add_section("Resource Type", "resource", "resourceType")
    add_section("Created At", "createdAt")
    add_section("Type", "type")
    add_section("Region", "region")

    # Conditionally add sections based on resource type
    resource_type = finding["detail"].get("resource", {}).get("resourceType")
    logging.info(f"resource_type: {resource_type}")

    resource_specific_sections = {
        "AccessKey": [
            ("Access Key ID", "resource", "accessKeyDetails", "accessKeyId"),
            ("User Name", "resource", "accessKeyDetails", "userName"),
        ],
        "Instance": [
            ("Instance ID", "resource", "instanceDetails", "instanceId"),
            ("Instance Type", "resource", "instanceDetails", "instanceType"),
        ],
        "ECSCluster": [("ECS Cluster Name", "resource", "containerDetails", "name")],
        "Lambda": [
            ("Lambda Name", "resource", "lambdaDetails", "functionName"),
            ("Lambda Description", "resource", "lambdaDetails", "description"),
        ],
        "Container": [
            ("Container Runtime", "resource", "containerDetails", "containerRuntime"),
            ("Container Name", "resource", "containerDetails", "name"),
            ("Container Image", "resource", "containerDetails", "image"),
        ],
        "EKSCluster": [
            ("EKS Cluster Name", "resource", "eksClusterDetails", "name"),
            (
                "Workload Details",
                "resource",
                "kubernetesDetails",
                "kubernetesWorkloadDetails",
                "name",
            ),
            ("Container Name", "resource", "containerDetails", "name"),
        ],
    }

    for values in resource_specific_sections.get(resource_type, []):
        logging.info(f"values: {values}")
        add_section(*values)

    # Additional fields
    action_type = (
        finding.get("detail", {}).get("service", {}).get("action", {}).get("actionType")
    )
    if action_type:
        sections.append(f"Action Type: <span class='value'>{action_type}</span>")

    # Convert the sections into div elements
    sections_html = f"""
        <div class="section">
            <div class="section-title">GuardDuty Information</div>
            {"".join(sections)}
        </div>
        """
    return sections_html


def get_guardduty_url(event):
    """Constructs a URL to the GuardDuty finding in the AWS Management Console."""
    guardduty_id = get_nested_value(event, ["detail", "id"])
    region = get_nested_value(event, ["detail", "region"])

    return f"https://{region}.console.aws.amazon.com/guardduty/home?region={region}#/findings?macros=current&fId={guardduty_id}"
