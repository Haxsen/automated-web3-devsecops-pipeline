# -------------------------------------------------------------------------------------------------
# GitHub Actions → AWS via OIDC: short-lived credentials, zero long-lived access keys.
# -------------------------------------------------------------------------------------------------
resource "aws_iam_openid_connect_provider" "github" {
  count = var.create_github_oidc_provider ? 1 : 0

  url            = "https://${local.github_oidc_host}"
  client_id_list = ["sts.amazonaws.com"]
}

data "aws_iam_policy_document" "github_deployer_trust" {
  statement {
    sid     = "GitHubActionsDeployEnvironmentOnly"
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [local.github_oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.github_oidc_host}:aud"
      values   = ["sts.amazonaws.com"]
    }

    # Exact match (StringEquals, never StringLike/wildcards). Enforced by policies/terraform/github_oidc.rego.
    condition {
      test     = "StringEquals"
      variable = "${local.github_oidc_host}:sub"
      values   = [local.github_deploy_subject]
    }
  }
}

resource "aws_iam_role" "github_deployer" {
  name                 = "${local.name}-github-deployer"
  description          = "Assumed by the ${var.environment} deploy job in ${var.github_repository} via OIDC."
  assume_role_policy   = data.aws_iam_policy_document.github_deployer_trust.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "github_deployer_permissions" {
  statement {
    sid       = "SignWithDeployerKeyOnly"
    effect    = "Allow"
    actions   = ["kms:Sign"]
    resources = [aws_kms_key.deployer.arn]
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
    sid       = "ReadDeployerPublicKey"
    effect    = "Allow"
    actions   = ["kms:GetPublicKey", "kms:DescribeKey"]
    resources = [aws_kms_key.deployer.arn]
  }

  statement {
    sid       = "ReadRpcEndpointSecret"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.rpc_url.arn]
  }

  statement {
    sid       = "DecryptRpcEndpointSecret"
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.platform.arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${local.region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "github_deployer" {
  name   = "deployer-least-privilege"
  role   = aws_iam_role.github_deployer.id
  policy = data.aws_iam_policy_document.github_deployer_permissions.json
}
