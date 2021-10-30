# Cloud Watch Alarm to ZenDesk

Provides a way to send CloudWatch Alarm State changes through to tickets in Zendesk.
If the alarm has already created an incident which is active it will add a comment to the existing ticket

Tickets are created in the format of

```plaintext
Subject:
    AWS Alarm - < Your CloudWatch Alarm Name>

Description:
    An AWS CloudWatch Alarm has changed state to <CloudWatch Alarm State>"

    - Description: <Description of CloudWatch Alarm>
    - New State: <CloudWatch Alarm State>
    - Reason for Change: <CloudWatch State Change Reason>

    - Region: <AWS Region>
    - AWSAccountId: < AWS Account Id>

    - Metric Namespace: <Metric Namespace>
    - Metric Name: <Metric Name>
```

## Configuration

Environment Variables

* ZENDESK_SUBDOMAIN - required - The subdomain of your zendesk instance
* ZENDESK_OAUTH_TOKEN - required -An oAuth token generated for this lambda function to use
* ZENDESK_ALARM_NAME - required - The name of the user in zendesk who will be set as the requester
* ZENDESK_ORGANIZATION - optional - The name of an organization that the ticket and user will belong to
* ZENDESK_USER_TAGS - optional - A space separated list of tags to add to the ticket

* KMS_PREFIX - a prefix added to the base64 + kms encoded OAUTH Token if you are using encryption
* SENTRY_DSN - a sentry DSN for exception reporting

## oAuth Token Generation

The lambda function requires an oAuth token which has been provided from the [Zendesk API](https://developer.zendesk.com/documentation/ticketing/working-with-oauth/creating-and-using-oauth-tokens-with-the-api/
)

When requesting the token you will need to request the scopes `tickets:write read`. This gives lambda function the ability to create tickets and run searches across your zendesk deployment

## Testing

You can run the script locally using the lambda-local-run python package ( included in requirements )

To test you will need an active Zendesk account along with an OAuth token

```bash
npm install
pip install -r requirements.txt
npx sls invoke local -f cloudwatch-zendesk --path test_events/event.json --env ZENDESK_SUBDOMAIN=<SubDomain> --env ZENDESK_OAUTH_TOKEN=<OAuth Token> --env ZENDESK_ALARM_NAME=<Test User Name>  --env ZENDESK_ORGANISATION=<Organization Name>
```

## Packaging

To create a zip package for lambda deployment

```bash
npx sls package
```

This will create the lambda.zip and place it `.serverless/cloudwatch-zendesk.zip`

## oAuth Token Encryption

Since the oAuth token should be treated as a password we recommend encrypting it. If you are using hamlet for your deployment run the following command

```bash
hamlet manage crypto -e -t 'your oAuth Token'
```

And save the value generated as a setting with the kms prefix appended.

```json
{
    "ZENDESK_OUTH_TOKEN" : "kms+base64:<encrypted token>"
}
```

### KMS IAM Permissions Required

If you are using an encrypted token ensure your lambda function has the following permissions

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "Stmt1443036478000",
            "Effect": "Allow",
            "Action": [
                "kms:Decrypt"
            ],
            "Resource": [
                "<your KMS key ARN>"
            ]
        }
    ]
}
```
