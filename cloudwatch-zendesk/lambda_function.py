import boto3
import json
import logging
import os
import re

import sentry_sdk

from zenpy import Zenpy
from base64 import b64decode
from sentry_sdk.integrations.logging import LoggingIntegration
from zenpy.lib.api_objects import Ticket, User, Comment

# The base-64 encoded, encrypted key (CiphertextBlob) stored in the kmsEncryptedHookUrl environment variable
ZENDESK_SUBDOMAIN = os.environ["ZENDESK_SUBDOMAIN"]
ZENDESK_OAUTH_TOKEN = os.environ["ZENDESK_OAUTH_TOKEN"]

ZENDESK_ALARM_NAME = os.environ["ZENDESK_ALARM_NAME"]

ZENDESK_ORGANIZATION = os.environ.get("ZENDESK_ORGANIZATION", None)
ZENDESK_USER_TAGS = os.environ.get("ZENDESK_USER_TAGS", None)

SENTRY_DSN = os.environ.get("SENTRY_DSN", None)
KMS_PREFIX = os.environ.get("KMS_PREFIX", "kms+base64:")

# Decrypt Token encrypted in kms + b64 encoded
if isinstance(ZENDESK_OAUTH_TOKEN, (str, bytes)) and ZENDESK_OAUTH_TOKEN.startswith(
    KMS_PREFIX
):
    ENCRYPTED_OAUTH_TOKEN = ZENDESK_OAUTH_TOKEN[len(KMS_PREFIX) :]
    ZENDESK_OAUTH_TOKEN = (
        boto3.client("kms")
        .decrypt(CiphertextBlob=b64decode(ENCRYPTED_OAUTH_TOKEN))["Plaintext"]
        .decode("utf-8")
    )

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Sentry using the Logging Integration
sentry_logging = LoggingIntegration(level=logging.INFO, event_level=logging.ERROR)

sentry_sdk.init(
    dsn=SENTRY_DSN,
    integrations=[sentry_logging],
)

zenpy_client = Zenpy(subdomain=ZENDESK_SUBDOMAIN, oauth_token=ZENDESK_OAUTH_TOKEN)
zenpy_client.disable_caching()


def get_existing_ticket(client, user, tags):
    tickets = client.search(type="ticket", requester=user.id)

    for ticket in tickets:
        tags.sort()
        ticket_tags = [tag for tag in ticket.tags if tag.startswith("cw:")]
        ticket_tags.sort()

        if (
            len(set(tags).intersection(set(ticket_tags))) == len(set(tags))
            and ticket.status != "solved"
        ):
            return ticket

    return None


def get_user(client, requester_name, organization):
    logger.info(f"Looking for user {requester_name}")

    users = client.users.search(requester_name)
    for user in users:
        if organization is not None:
            if user.organization_id == organization.id:
                logger.info(f"Found existing user #{user.id}")
                return user
        else:
            return user

    user_properties = {"name": requester_name}

    if organization is not None:
        user_properties["organization_id"] = organization.id

    user = client.users.create(User(**user_properties))
    logger.info(f"Created new user #{user.id}")
    return user


def get_organization(client, organization_name):
    logger.info(f"Looking for organization {organization_name}")

    if organization_name is not None:
        organizations = client.search(organization_name, type="organization")

        for organization in organizations:
            logger.info(f"Found organization #{organization.id}")
            return organization

    return None


def lambda_handler(event, context):
    message = json.loads(event["Records"][0]["Sns"]["Message"])

    alarm_name = message["AlarmName"]

    if re.match("^\w*\|", alarm_name) is not None:
        alarm_severity = alarm_name.split("|")[0]
    else:
        alarm_severity = alarm_name.split("-")[0]

    logger.info(f"Alarm {alarm_name} - Severity: {alarm_severity}")

    new_state = message["NewStateValue"]

    alarm_description = message["AlarmDescription"]
    if "Namespace" in message["Trigger"]:
        namespace = message["Trigger"]["Namespace"]
    else:
        namespace = message["Trigger"]["Metrics"][0]["MetricStat"]["Metric"][
            "Namespace"
        ]
    if "MetricName" in message["Trigger"]:
        metric_name = message["Trigger"]["MetricName"]
    else:
        metric_name = message["Trigger"]["Metrics"][0]["MetricStat"]["Metric"][
            "MetricName"
        ]
    reason = message["NewStateReason"]
    region = message["Region"]
    accountId = message["AWSAccountId"]

    tag_alarm_name = alarm_name.lower()
    tag_alarm_name = re.sub("[^0-9a-zA-Z]+", "_", tag_alarm_name)

    tag_alarm_region = region.lower()
    tag_alarm_region = re.sub("[^0-9a-zA-Z]+", "_", tag_alarm_region)

    tags = [
        f"cw:name:{tag_alarm_name}",
        f"cw:region:{tag_alarm_region}",
        f"cw:accountid:{accountId}",
    ]

    organization = get_organization(
        client=zenpy_client, organization_name=ZENDESK_ORGANIZATION
    )
    user = get_user(
        client=zenpy_client,
        requester_name=ZENDESK_ALARM_NAME,
        organization=organization,
    )

    existing_ticket = get_existing_ticket(zenpy_client, user, tags)
    if existing_ticket is not None:

        logger.info(f"Adding state change comment to ticket #{existing_ticket.id}")
        comment = f"Alarm has changed state to {new_state}\n" f"Reason: {reason}\n"

        ticket = zenpy_client.tickets(id=existing_ticket.id)
        ticket.comment = Comment(body=comment, author_id=ticket.requester_id)
        zenpy_client.tickets.update(ticket)

    if existing_ticket is None:

        logger.info(f"Creating new ticket for alarm {alarm_name}")
        description = (
            f"An AWS CloudWatch Alarm has changed state to {new_state}\n"
            "\n"
            f"- Description: {alarm_description}\n"
            f"- New State: {new_state}\n"
            f"- Reason for Change: {reason}\n"
            "\n"
            f"- Region: {region}\n"
            f"- AWSAccountId: {accountId}\n"
            "\n"
            f"- Metric Namespace: {namespace}\n"
            f"- Metric Name: {metric_name}\n"
        )

        if ZENDESK_USER_TAGS is not None:
            tags.append([tag.lower() for tag in ZENDESK_USER_TAGS.split(" ")])

        ticket_content = {
            "subject": f"AWS Alarm - {alarm_name}",
            "description": description,
            "requester_id": user.id,
            "tags": tags,
        }

        if organization is not None:
            ticket_content["organization_id"] = organization.id

        ticket_audit = zenpy_client.tickets.create(Ticket(**ticket_content))
        logger.info(f"Created new ticket #{ticket_audit.ticket.id}")
