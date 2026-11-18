# Secret-handling guardrails: no key material or secret values in Terraform code or state.
package terraform.secrets

import data.lib.terraform as tf

# Secrets must be encrypted with a customer-managed key (auditable, revocable), not the AWS-managed default.
deny contains msg if {
	some name, secret in tf.resources("aws_secretsmanager_secret")
	not secret.kms_key_id
	msg := sprintf("aws_secretsmanager_secret.%s: set kms_key_id to a customer-managed KMS key", [name])
}

deny contains msg if {
	some name, secret in tf.resources("aws_secretsmanager_secret")
	object.get(secret, "recovery_window_in_days", 30) == 0
	msg := sprintf("aws_secretsmanager_secret.%s: recovery_window_in_days = 0 allows instant, unrecoverable deletion", [name])
}

# Anything in secret_string is stored in plaintext in Terraform state. Set values out-of-band instead.
deny contains msg if {
	some name, version in tf.resources("aws_secretsmanager_secret_version")
	some attr in ["secret_string", "secret_binary"]
	version[attr]
	msg := sprintf("aws_secretsmanager_secret_version.%s: %s would be written to Terraform state; set the value out-of-band", [name, attr])
}

# Signing material belongs in KMS. It must never be passed into Terraform as an input variable.
deny contains msg if {
	some name, _ in tf.variables
	some marker in ["private_key", "privatekey", "mnemonic", "seed_phrase", "signer_key"]
	contains(lower(name), marker)
	msg := sprintf("variable.%s: on-chain signing material must live in KMS, never in Terraform variables", [name])
}

# Catch raw 32-byte hex strings (the shape of an Ethereum private key) anywhere in the configuration.
deny contains msg if {
	some file in input
	walk(file.contents, [path, value])
	is_string(value)
	regex.match(`^(0x)?[0-9a-fA-F]{64}$`, value)
	msg := sprintf("%s: value at %v looks like a raw private key", [file.path, path])
}
