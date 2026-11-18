variable "project" {
  description = "Short project name used to prefix every resource."
  type        = string
  default     = "secure-vault"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,30}$", var.project))
    error_message = "project must be 3-31 chars of lowercase letters, digits and hyphens."
  }
}

variable "environment" {
  description = "Deployment environment (also the GitHub Environment allowed to assume the deploy role)."
  type        = string
  default     = "sepolia"

  validation {
    condition     = can(regex("^[a-z0-9-]{2,20}$", var.environment))
    error_message = "environment must be 2-20 chars of lowercase letters, digits and hyphens."
  }
}

variable "aws_region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "eu-west-1"
}

variable "github_repository" {
  description = "GitHub repository (owner/name) whose deploy workflow may assume the deploy role."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.github_repository))
    error_message = "github_repository must look like owner/name, with no wildcards."
  }
}

variable "create_github_oidc_provider" {
  description = "Create the GitHub Actions OIDC identity provider. Set false if the account already has one."
  type        = bool
  default     = true
}

variable "key_admin_role_arns" {
  description = "IAM role ARNs allowed to administer (but never use) the KMS keys, e.g. a break-glass admin role."
  type        = list(string)

  validation {
    condition     = length(var.key_admin_role_arns) > 0 && alltrue([for arn in var.key_admin_role_arns : can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:role/.+$", arn))])
    error_message = "Provide at least one IAM role ARN; key admins are required to avoid an unmanageable key."
  }
}

variable "security_alert_emails" {
  description = "Email addresses subscribed to deployer-key security alerts."
  type        = list(string)
  default     = []
}

variable "log_retention_days" {
  description = "Retention for the security audit log group."
  type        = number
  default     = 365
}
