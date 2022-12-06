import boto3
import json
import os

USER_DYNAMODB_TABLE = os.environ["USER_DYNAMODB_TABLE"]
ORGANISATION_USER_DYNAMODB_TABLE = os.environ["ORGANISATION_USER_DYNAMODB_TABLE"]
ORGANISATION_DYNAMODB_TABLE = os.environ["ORGANISATION_DYNAMODB_TABLE"]
DOMAIN_ORGANISATION_DYNAMODB_TABLE = os.environ["DOMAIN_ORGANISATION_DYNAMODB_TABLE"]
DOMAIN_DYNAMODB_TABLE = os.environ["DOMAIN_DYNAMODB_TABLE"]
SSH_KEY_PAIR_USER_DYNAMODB_TABLE = os.environ["SSH_KEY_PAIR_USER_DYNAMODB_TABLE"]
SSH_KEY_PAIR_DYNAMODB_TABLE = os.environ["SSH_KEY_PAIR_DYNAMODB_TABLE"]
SSH_PUBLIC_KEY_DYNAMODB_TABLE = os.environ["SSH_PUBLIC_KEY_DYNAMODB_TABLE"]

dynamodb_client = boto3.client("dynamodb")
dynamodb_resource = boto3.resource("dynamodb")

dynamodb_user_table = dynamodb_resource.Table(USER_DYNAMODB_TABLE)
dynamodb_organisation_user_table = dynamodb_resource.Table(
    ORGANISATION_USER_DYNAMODB_TABLE
)
dynamodb_organisation_table = dynamodb_resource.Table(ORGANISATION_DYNAMODB_TABLE)
dynamodb_domain_organisation_table = dynamodb_resource.Table(
    DOMAIN_ORGANISATION_DYNAMODB_TABLE
)
dynamodb_domain_table = dynamodb_resource.Table(DOMAIN_DYNAMODB_TABLE)
dynamodb_ssh_key_pair_user_table = dynamodb_resource.Table(
    SSH_KEY_PAIR_USER_DYNAMODB_TABLE
)
dynamodb_ssh_key_pair_table = dynamodb_resource.Table(SSH_KEY_PAIR_DYNAMODB_TABLE)
dynamodb_ssh_public_key_table = dynamodb_resource.Table(SSH_PUBLIC_KEY_DYNAMODB_TABLE)


COGNITO_USER_POOL_ID = os.environ["COGNITO_USER_POOL_ID"]

cognito_idp_client = boto3.client("cognito-idp")


def handler(event, context):
    user_id = event["user_id"]

    list_users_response = cognito_idp_client.list_users(
        UserPoolId=COGNITO_USER_POOL_ID,
        AttributesToGet=[
            'string',
        ],
        Limit=10,
        Filter=f'email = "{user_id}"',
    )
    cognito_usernames = [user["Username"] for user in list_users_response["Users"]]
    for cognito_username in cognito_usernames:
        cognito_idp_client.admin_delete_user(
            UserPoolId=COGNITO_USER_POOL_ID,
            Username=cognito_username,
        )

    transact_items = []
    organisation_user_query_result = dynamodb_organisation_user_table.query(
        KeyConditionExpression="#sourceId = :sourceId",
        ExpressionAttributeNames={
            "#sourceId": "sourceId",
        },
        ExpressionAttributeValues={
            ":sourceId": user_id,
        },
    )

    organisation_ids = [
        item["targetId"] for item in organisation_user_query_result["Items"]
    ]
    for organisation_id in organisation_ids:
        domain_organisation_query_result = dynamodb_domain_organisation_table.query(
            KeyConditionExpression="#sourceId = :sourceId",
            ExpressionAttributeNames={
                "#sourceId": "sourceId",
            },
            ExpressionAttributeValues={
                ":sourceId": organisation_id,
            },
        )
        domain_ids = [
            item["targetId"] for item in domain_organisation_query_result["Items"]
        ]

        for domain_id in domain_ids:
            transact_items.extend(
                [
                    {
                        "Delete": {
                            "TableName": DOMAIN_ORGANISATION_DYNAMODB_TABLE,
                            "Key": {
                                "sourceId": {"S": organisation_id},
                                "targetId": {"S": domain_id},
                            },
                            "ConditionExpression": "attribute_exists(#sourceId)",
                            "ExpressionAttributeNames": {
                                "#sourceId": "sourceId",
                            },
                        },
                    },
                    {
                        "Delete": {
                            "TableName": DOMAIN_DYNAMODB_TABLE,
                            "Key": {"id": {"S": domain_id}},
                            "ConditionExpression": "attribute_exists(#id)",
                            "ExpressionAttributeNames": {
                                "#id": "id",
                            },
                        },
                    },
                ]
            )

        transact_items.extend(
            [
                {
                    "Delete": {
                        "TableName": ORGANISATION_DYNAMODB_TABLE,
                        "Key": {"id": {"S": organisation_id}},
                        "ConditionExpression": "#User_linkCount = :one and #linkCount = :expectedLinkCount",
                        "ExpressionAttributeNames": {
                            "#User_linkCount": "__User_linkCount",
                            "#linkCount": "__linkCount",
                        },
                        "ExpressionAttributeValues": {
                            ":one": {
                                "N": "1",
                            },
                            ":expectedLinkCount": {
                                "N": str(1 + len(domain_ids)),
                            },
                        },
                    },
                },
                {
                    "Delete": {
                        "TableName": ORGANISATION_USER_DYNAMODB_TABLE,
                        "Key": {
                            "sourceId": {"S": user_id},
                            "targetId": {"S": organisation_id},
                        },
                        "ConditionExpression": "attribute_exists(#sourceId)",
                        "ExpressionAttributeNames": {
                            "#sourceId": "sourceId",
                        },
                    },
                },
                {
                    "Delete": {
                        "TableName": ORGANISATION_USER_DYNAMODB_TABLE,
                        "Key": {
                            "sourceId": {"S": organisation_id},
                            "targetId": {"S": user_id},
                        },
                        "ConditionExpression": "attribute_exists(#sourceId)",
                        "ExpressionAttributeNames": {
                            "#sourceId": "sourceId",
                        },
                    },
                },
            ]
        )

    ssh_key_pair_user_query_result = dynamodb_ssh_key_pair_user_table.query(
        KeyConditionExpression="#sourceId = :sourceId",
        ExpressionAttributeNames={
            "#sourceId": "sourceId",
        },
        ExpressionAttributeValues={
            ":sourceId": user_id,
        },
    )
    ssh_key_pair_ids = [
        item["targetId"] for item in ssh_key_pair_user_query_result["Items"]
    ]
    for ssh_key_pair_id in ssh_key_pair_ids:
        ssh_key_pair_get_item_result = dynamodb_ssh_key_pair_table.get_item(
            Key={"id": ssh_key_pair_id},
        )
        ssh_key_pair = ssh_key_pair_get_item_result["Item"]
        ssh_public_key_id = ssh_key_pair["SshPublicKeyId"]

        transact_items.extend(
            [
                {
                    "Delete": {
                        "TableName": SSH_KEY_PAIR_USER_DYNAMODB_TABLE,
                        "Key": {
                            "sourceId": {"S": user_id},
                            "targetId": {"S": ssh_key_pair_id},
                        },
                        "ConditionExpression": "attribute_exists(#sourceId)",
                        "ExpressionAttributeNames": {
                            "#sourceId": "sourceId",
                        },
                    },
                },
                {
                    "Delete": {
                        "TableName": SSH_KEY_PAIR_DYNAMODB_TABLE,
                        "Key": {"id": {"S": ssh_key_pair_id}},
                        "ConditionExpression": "attribute_exists(#id)",
                        "ExpressionAttributeNames": {
                            "#id": "id",
                        },
                    },
                },
                {
                    "Delete": {
                        "TableName": SSH_PUBLIC_KEY_DYNAMODB_TABLE,
                        "Key": {"id": {"S": ssh_public_key_id}},
                        "ConditionExpression": "attribute_exists(#id)",
                        "ExpressionAttributeNames": {
                            "#id": "id",
                        },
                    },
                },
            ]
        )

    transact_items.append(
        {
            "Delete": {
                "TableName": USER_DYNAMODB_TABLE,
                "Key": {"id": {"S": user_id}},
                "ConditionExpression": (
                    "#Organisation_linkCount = :expectedOrganisationLinkCount and "
                    "#linkCount = :expectedLinkCount and "
                )
                + (
                    "#SshKeyPair_linkCount = :expectedSshKeyPairLinkCount"
                    if len(ssh_key_pair_ids)
                    else "(#SshKeyPair_linkCount = :expectedSshKeyPairLinkCount or attribute_not_exists(#SshKeyPair_linkCount))"
                ),
                "ExpressionAttributeNames": {
                    "#Organisation_linkCount": "__Organisation_linkCount",
                    "#SshKeyPair_linkCount": "__SshKeyPair_linkCount",
                    "#linkCount": "__linkCount",
                },
                "ExpressionAttributeValues": {
                    ":expectedLinkCount": {
                        "N": str(len(organisation_ids) + len(ssh_key_pair_ids)),
                    },
                    ":expectedSshKeyPairLinkCount": {
                        "N": str(len(ssh_key_pair_ids)),
                    },
                    ":expectedOrganisationLinkCount": {
                        "N": str(len(organisation_ids)),
                    },
                },
            },
        }
    )

    print(json.dumps(transact_items))

    result = dynamodb_client.transact_write_items(
        TransactItems=transact_items,
    )
    print(json.dumps(result))

    return result


if __name__ == "__main__":
    import sys
    user_id = sys.argv[1]
    handler({"user_id": user_id}, {})
