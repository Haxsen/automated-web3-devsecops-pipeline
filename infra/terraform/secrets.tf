# -------------------------------------------------------------------------------------------------
# Authenticated RPC endpoint (provider URL contains an API key).
# Terraform creates the *container* only. The value is written out-of-band, e.g.
#   aws secretsmanager put-secret-value --secret-id <arn> --secret-string "$RPC_URL"
# so the secret never lands in Terraform state or plan output.
# -------------------------------------------------------------------------------------------------
resource "aws_secretsmanager_secret" "rpc_url" {
  #checkov:skip=CKV2_AWS_57:Third-party RPC API keys cannot be rotated by a Lambda; rotation is done in the provider dashboard per docs/THREAT_MODEL.md.
  name                    = "${local.name}/rpc-url"
  description             = "Authenticated JSON-RPC endpoint used by the ${var.environment} deploy job."
  kms_key_id              = aws_kms_key.platform.arn
  recovery_window_in_days = 30
}
