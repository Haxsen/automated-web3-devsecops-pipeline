# -------------------------------------------------------------------------------------------------
# Deployer signing key: secp256k1 key held in AWS KMS (FIPS 140-3 HSMs).
# The private key is generated inside KMS and can never be exported, so there is no plaintext
# deployer key anywhere (not in GitHub secrets, a .env file, or a laptop). Foundry signs through
# KMS with `forge script --aws`.
# -------------------------------------------------------------------------------------------------
resource "aws_kms_key" "deployer" {
  #checkov:skip=CKV_AWS_7:Asymmetric (ECC_SECG_P256K1) keys cannot be auto-rotated by AWS; rotating would also change the on-chain address. Rotation is a runbook-driven ownership transfer.
  description              = "${local.name} contract deployer signing key (secp256k1)"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_SECG_P256K1"
  deletion_window_in_days  = 30
  enable_key_rotation      = false
  policy                   = data.aws_iam_policy_document.deployer_key.json

  # Losing this key means losing ownership of every contract it deployed.
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_kms_alias" "deployer" {
  name          = "alias/${local.name}-deployer"
  target_key_id = aws_kms_key.deployer.key_id
}

data "aws_iam_policy_document" "deployer_key" {
  #checkov:skip=CKV_AWS_109:KMS key policy, so Resource "*" means "this key" and admins are a fixed role list.
  #checkov:skip=CKV_AWS_111:KMS key policy, so Resource "*" means "this key" and admins are a fixed role list.
  #checkov:skip=CKV_AWS_356:KMS key policy, so Resource "*" means "this key".

  # Separation of duties: administrators manage the key lifecycle but are NOT granted kms:Sign.
  statement {
    sid    = "KeyAdministration"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = var.key_admin_role_arns
    }
    actions = [
      "kms:CancelKeyDeletion",
      "kms:Describe*",
      "kms:Disable*",
      "kms:Enable*",
      "kms:Get*",
      "kms:List*",
      "kms:Put*",
      "kms:Revoke*",
      "kms:ScheduleKeyDeletion",
      "kms:TagResource",
      "kms:UntagResource",
      "kms:Update*",
    ]
    resources = ["*"]
  }

  # Only the CI deploy role can sign, and only raw 32-byte digests with ECDSA (what an Ethereum signer needs).
  statement {
    sid    = "DeployerSignOnly"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.github_deployer.arn]
    }
    actions   = ["kms:Sign"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:SigningAlgorithm"
      values   = ["ECDSA_SHA_256"]
    }
    condition {
      test     = "StringEquals"
      variable = "kms:MessageType"
      values   = ["DIGEST"]
    }
  }

  statement {
    sid    = "DeployerReadPublicKey"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.github_deployer.arn]
    }
    actions   = ["kms:GetPublicKey", "kms:DescribeKey"]
    resources = ["*"]
  }
}

# -------------------------------------------------------------------------------------------------
# Symmetric CMK protecting secrets, alert topic and audit logs.
# -------------------------------------------------------------------------------------------------
resource "aws_kms_key" "platform" {
  description             = "${local.name} platform encryption key (secrets, SNS, logs)"
  enable_key_rotation     = true
  rotation_period_in_days = 90
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.platform_key.json
}

resource "aws_kms_alias" "platform" {
  name          = "alias/${local.name}-platform"
  target_key_id = aws_kms_key.platform.key_id
}

data "aws_iam_policy_document" "platform_key" {
  #checkov:skip=CKV_AWS_109:KMS key policy, so Resource "*" means "this key" and admins are a fixed role list.
  #checkov:skip=CKV_AWS_111:KMS key policy, so Resource "*" means "this key" and admins are a fixed role list.
  #checkov:skip=CKV_AWS_356:KMS key policy, so Resource "*" means "this key".

  statement {
    sid    = "KeyAdministration"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = var.key_admin_role_arns
    }
    actions = [
      "kms:CancelKeyDeletion",
      "kms:Describe*",
      "kms:Disable*",
      "kms:Enable*",
      "kms:Get*",
      "kms:List*",
      "kms:Put*",
      "kms:Revoke*",
      "kms:ScheduleKeyDeletion",
      "kms:TagResource",
      "kms:UntagResource",
      "kms:Update*",
    ]
    resources = ["*"]
  }

  # The deploy role may decrypt only through Secrets Manager in this account and region.
  statement {
    sid    = "DeployerDecryptViaSecretsManager"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.github_deployer.arn]
    }
    actions   = ["kms:Decrypt"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${local.region}.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid    = "AllowEventBridgeToPublishEncryptedAlerts"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    actions   = ["kms:Decrypt", "kms:GenerateDataKey*"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid    = "AllowCloudWatchLogsEncryption"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logs.${local.region}.amazonaws.com"]
    }
    actions   = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
    resources = ["*"]
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:${local.partition}:logs:${local.region}:${local.account_id}:log-group:/${var.project}/*"]
    }
  }
}
