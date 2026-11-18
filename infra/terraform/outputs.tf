output "deployer_key_arn" {
  description = "KMS key used by `forge script --aws` (export as AWS_KMS_KEY_ID)."
  value       = aws_kms_key.deployer.arn
}

output "deployer_key_alias" {
  description = "Alias of the deployer signing key."
  value       = aws_kms_alias.deployer.name
}

output "github_deployer_role_arn" {
  description = "Role assumed by the deploy workflow via OIDC (set as the AWS_DEPLOY_ROLE_ARN environment variable in GitHub)."
  value       = aws_iam_role.github_deployer.arn
}

output "rpc_url_secret_arn" {
  description = "Secrets Manager secret holding the authenticated RPC URL (set its value out-of-band)."
  value       = aws_secretsmanager_secret.rpc_url.arn
}

output "security_alerts_topic_arn" {
  description = "SNS topic that receives deployer-key activity alerts."
  value       = aws_sns_topic.security_alerts.arn
}
