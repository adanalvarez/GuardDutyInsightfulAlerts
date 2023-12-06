resource "aws_cloudwatch_event_rule" "guardduty_cloudwatch_event_rule" {
  name          = "guardduty-finding-events"
  description   = "AWS GuardDuty event findings"
  event_pattern = file("${path.module}/event-pattern.json")
}

resource "aws_cloudwatch_event_target" "guardduty_cloudwatch_event_target" {
  rule      = aws_cloudwatch_event_rule.guardduty_cloudwatch_event_rule.name
  target_id = "alert-to-lambda"
  arn       = module.lambda_function.lambda_function_arn                
}