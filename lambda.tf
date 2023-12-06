locals {
  layer_zip_path    = "layer/layer.zip"
  layer_name        = "requests_layer"
  requirements_path = "${path.root}/layer/requirements.txt"
}

# Create zip file from requirements.txt. Triggers only when the file is updated
resource "null_resource" "build_lambda_layer" {
  triggers = {
    requirements = filesha1(local.requirements_path)
  }
  # the command to install python and dependencies to the machine and zips
  provisioner "local-exec" {
    command = "${path.module}/layer/build.sh"
  }
}

# Create lambda layer from zip file
resource "aws_lambda_layer_version" "guardduty_insight_lambdas_layer" {
  layer_name          = local.layer_name
  compatible_runtimes = ["python3.11"]
  skip_destroy        = true
  filename            = local.layer_zip_path
  source_code_hash    = filebase64sha256(local.layer_zip_path)
}

module "lambda_function" {
  source = "terraform-aws-modules/lambda/aws"
  version = "6.5.0"
  function_name = "guardduty-insight-alerts"
  description   = "Lambda to enrich GuardDuty events"
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.11"
  layers = [
    aws_lambda_layer_version.guardduty_insight_lambdas_layer.arn
  ]
  source_path = "src/"
  timeout = 120
  tags = {
    Name = "GuardDuty-Insight-Alerts"
  }
  attach_policy_json = true
  policy_json = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        "Sid" : "GetEventDataStore",
        "Effect" : "Allow",
        "Action" : [
          "cloudtrail:GetEventDataStore",
          "cloudtrail:StartQuery",
          "cloudtrail:GetQueryResults"
        ],
        "Resource" : [
          var.event_data_store
        ]
      },
      {
        "Sid" : "SendEmail",
        "Effect" : "Allow",
        "Action" : [
          "ses:SendEmail"
        ],
        "Resource" : [
          var.ses_identity
        ]
      }
    ]
  })

  environment_variables = {
    EVENT_DATA_STORE = var.event_data_store
    VPNAPI_KEY = var.vpnapi_key
    DESTINATION_EMAIL = var.destination_email
    SOURCE_EMAIL = var.source_email
  }

}

resource "aws_lambda_permission" "allow_cloudwatch_to_call_guardduty_insight_lambda" {
    statement_id = "AllowExecutionFromCloudWatch"
    action = "lambda:InvokeFunction"
    function_name = module.lambda_function.lambda_function_name
    principal = "events.amazonaws.com"
    source_arn = aws_cloudwatch_event_rule.guardduty_cloudwatch_event_rule.arn
}