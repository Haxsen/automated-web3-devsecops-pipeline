data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  name       = "${var.project}-${var.environment}"
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = data.aws_region.current.region

  github_oidc_host = "token.actions.githubusercontent.com"
  github_oidc_provider_arn = (
    var.create_github_oidc_provider
    ? aws_iam_openid_connect_provider.github[0].arn
    : "arn:${local.partition}:iam::${local.account_id}:oidc-provider/${local.github_oidc_host}"
  )

  # The ONLY workload identity that may sign transactions: the deploy job running in the protected GitHub
  # Environment (which enforces required reviewers). Branches, PRs and forks cannot produce this subject.
  github_deploy_subject = "repo:${var.github_repository}:environment:${var.environment}"
}
