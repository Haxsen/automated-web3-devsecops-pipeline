# Unit tests for the Terraform policies. Run with: conftest verify --policy policies/terraform
# Every deny rule has a test proving it fires, and compliant fixtures prove it stays quiet.
package terraform.policies_test

import data.terraform.github_oidc
import data.terraform.kms
import data.terraform.secrets

tf_file(contents) := [{"path": "test.tf", "contents": contents}]

any_message_contains(messages, fragment) if {
	some msg in messages
	contains(msg, fragment)
}

# --------------------------------------------------------------------------------------------------
# KMS
# --------------------------------------------------------------------------------------------------

signing_key := {
	"key_usage": "SIGN_VERIFY",
	"customer_master_key_spec": "ECC_SECG_P256K1",
	"deletion_window_in_days": 30,
	"lifecycle": [{"prevent_destroy": true}],
}

key_input(key) := tf_file({"resource": {"aws_kms_key": {"k": [key]}}})

policy_doc_input(stmt) := tf_file({"data": {"aws_iam_policy_document": {"p": [{"statement": [stmt]}]}}})

test_kms_compliant_signing_key_passes if {
	count(kms.deny) == 0 with input as key_input(signing_key)
}

test_kms_compliant_symmetric_key_passes if {
	count(kms.deny) == 0 with input as key_input({"enable_key_rotation": true, "deletion_window_in_days": 30})
}

test_kms_rejects_non_secp256k1_signing_key if {
	denies := kms.deny with input as key_input(object.union(signing_key, {"customer_master_key_spec": "ECC_NIST_P256"}))
	any_message_contains(denies, "secp256k1")
}

test_kms_rejects_destroyable_signing_key if {
	denies := kms.deny with input as key_input(object.remove(signing_key, ["lifecycle"]))
	any_message_contains(denies, "prevent_destroy")
}

test_kms_rejects_short_deletion_window if {
	denies := kms.deny with input as key_input(object.union(signing_key, {"deletion_window_in_days": 7}))
	any_message_contains(denies, "deletion_window_in_days")
}

test_kms_rejects_symmetric_key_without_rotation if {
	denies := kms.deny with input as key_input({"deletion_window_in_days": 30})
	any_message_contains(denies, "enable_key_rotation")
}

test_kms_rejects_admin_and_sign_in_one_statement if {
	stmt := {"sid": "God", "actions": ["kms:PutKeyPolicy", "kms:Sign"], "condition": [
		{"test": "StringEquals", "variable": "kms:SigningAlgorithm", "values": ["ECDSA_SHA_256"]},
		{"test": "StringEquals", "variable": "kms:MessageType", "values": ["DIGEST"]},
	]}
	denies := kms.deny with input as policy_doc_input(stmt)
	any_message_contains(denies, "split key administration from signing")
}

test_kms_rejects_unconstrained_sign if {
	denies := kms.deny with input as policy_doc_input({"sid": "Loose", "actions": ["kms:Sign"]})
	any_message_contains(denies, "kms:SigningAlgorithm")
	any_message_contains(denies, "kms:MessageType")
}

test_kms_rejects_wildcard_actions if {
	denies := kms.deny with input as policy_doc_input({"sid": "Star", "actions": ["kms:*"]})
	any_message_contains(denies, "enumerate actions explicitly")
}

# --------------------------------------------------------------------------------------------------
# GitHub OIDC trust
# --------------------------------------------------------------------------------------------------

aud_condition := {"test": "StringEquals", "variable": "token.actions.githubusercontent.com:aud", "values": ["sts.amazonaws.com"]}

trust_input(sub_condition) := policy_doc_input({
	"actions": ["sts:AssumeRoleWithWebIdentity"],
	"condition": [aud_condition, sub_condition],
})

sub_condition(test, value) := {"test": test, "variable": "token.actions.githubusercontent.com:sub", "values": [value]}

test_oidc_environment_subject_passes if {
	count(github_oidc.deny) == 0 with input as trust_input(sub_condition("StringEquals", "repo:acme/vault:environment:mainnet"))
}

test_oidc_main_branch_subject_passes if {
	count(github_oidc.deny) == 0 with input as trust_input(sub_condition("StringEquals", "repo:acme/vault:ref:refs/heads/main"))
}

test_oidc_rejects_wildcard_subject if {
	denies := github_oidc.deny with input as trust_input(sub_condition("StringEquals", "repo:acme/*"))
	any_message_contains(denies, "no wildcards")
}

test_oidc_rejects_string_like if {
	denies := github_oidc.deny with input as trust_input(sub_condition("StringLike", "repo:acme/vault:environment:mainnet"))
	any_message_contains(denies, "StringLike")
}

test_oidc_rejects_pull_request_subject if {
	denies := github_oidc.deny with input as trust_input(sub_condition("StringEquals", "repo:acme/vault:pull_request"))
	any_message_contains(denies, "repo:acme/vault:pull_request")
}

test_oidc_rejects_missing_subject if {
	denies := github_oidc.deny with input as policy_doc_input({"actions": ["sts:AssumeRoleWithWebIdentity"], "condition": [aud_condition]})
	any_message_contains(denies, "must pin")
}

test_oidc_rejects_missing_audience if {
	denies := github_oidc.deny with input as policy_doc_input({
		"actions": ["sts:AssumeRoleWithWebIdentity"],
		"condition": [sub_condition("StringEquals", "repo:acme/vault:environment:mainnet")],
	})
	any_message_contains(denies, ":aud")
}

test_oidc_resolves_locals_before_judging_subject if {
	files := [
		{"path": "main.tf", "contents": {"locals": [{"subject": "repo:${var.repo}:*"}]}},
		trust_input(sub_condition("StringEquals", "${local.subject}"))[0],
	]
	denies := github_oidc.deny with input as files
	any_message_contains(denies, "repo:${var.repo}:*")
}

# --------------------------------------------------------------------------------------------------
# Secrets and key material
# --------------------------------------------------------------------------------------------------

test_secrets_compliant_secret_passes if {
	count(secrets.deny) == 0 with input as tf_file({"resource": {"aws_secretsmanager_secret": {"s": [{"kms_key_id": "${aws_kms_key.k.arn}", "recovery_window_in_days": 30}]}}})
}

test_secrets_rejects_default_encryption if {
	denies := secrets.deny with input as tf_file({"resource": {"aws_secretsmanager_secret": {"s": [{}]}}})
	any_message_contains(denies, "kms_key_id")
}

test_secrets_rejects_force_delete if {
	denies := secrets.deny with input as tf_file({"resource": {"aws_secretsmanager_secret": {"s": [{"kms_key_id": "x", "recovery_window_in_days": 0}]}}})
	any_message_contains(denies, "recovery_window_in_days")
}

test_secrets_rejects_secret_value_in_state if {
	denies := secrets.deny with input as tf_file({"resource": {"aws_secretsmanager_secret_version": {"v": [{"secret_string": "${var.rpc_url}"}]}}})
	any_message_contains(denies, "Terraform state")
}

test_secrets_rejects_private_key_variable if {
	denies := secrets.deny with input as tf_file({"variable": {"deployer_private_key": [{"type": "string"}]}})
	any_message_contains(denies, "must live in KMS")
}

test_secrets_rejects_raw_hex_key if {
	# Built at runtime so no key-shaped literal is ever committed (and secret scanners stay quiet).
	fake_key := concat("", ["0x", concat("", [s | some _ in numbers.range(1, 32); s := "ab"])])
	denies := secrets.deny with input as tf_file({"locals": [{"signer": fake_key}]})
	any_message_contains(denies, "raw private key")
}
