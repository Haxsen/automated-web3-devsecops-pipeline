# Guardrails for KMS keys that hold on-chain signing authority.
package terraform.kms

import data.lib.terraform as tf

admin_actions := {"kms:*", "kms:Put*", "kms:PutKeyPolicy", "kms:ScheduleKeyDeletion", "kms:CreateGrant"}

sign_actions := {"*", "kms:*", "kms:Sign", "kms:Sign*"}

# EVM chains sign with secp256k1; any other curve yields signatures no chain will accept.
deny contains msg if {
	some name, key in tf.resources("aws_kms_key")
	key.key_usage == "SIGN_VERIFY"
	object.get(key, "customer_master_key_spec", "") != "ECC_SECG_P256K1"
	msg := sprintf("aws_kms_key.%s: SIGN_VERIFY keys must use customer_master_key_spec = ECC_SECG_P256K1 (secp256k1)", [name])
}

# Destroying the deployer key permanently loses ownership of every contract it controls.
deny contains msg if {
	some name, key in tf.resources("aws_kms_key")
	key.key_usage == "SIGN_VERIFY"
	not prevent_destroy(key)
	msg := sprintf("aws_kms_key.%s: signing keys must set lifecycle { prevent_destroy = true }", [name])
}

# The maximum pending-deletion window gives incident response 30 days to cancel a malicious deletion.
deny contains msg if {
	some name, key in tf.resources("aws_kms_key")
	object.get(key, "deletion_window_in_days", 30) < 30
	msg := sprintf("aws_kms_key.%s: deletion_window_in_days must be 30", [name])
}

# Symmetric keys must rotate (asymmetric keys cannot, which is why they are exempt).
deny contains msg if {
	some name, key in tf.resources("aws_kms_key")
	object.get(key, "key_usage", "ENCRYPT_DECRYPT") == "ENCRYPT_DECRYPT"
	object.get(key, "enable_key_rotation", false) != true
	msg := sprintf("aws_kms_key.%s: symmetric keys must set enable_key_rotation = true", [name])
}

# Separation of duties: whoever can rewrite the key policy or delete the key must not also be able to sign.
deny contains msg if {
	some name, doc in tf.data_sources("aws_iam_policy_document")
	some stmt in doc.statement
	object.get(stmt, "effect", "Allow") == "Allow"
	some admin in stmt.actions
	admin in admin_actions
	some sign in stmt.actions
	sign in sign_actions
	msg := sprintf("data.aws_iam_policy_document.%s (sid %q): grants both %q and %q; split key administration from signing", [name, object.get(stmt, "sid", "<none>"), admin, sign])
}

# Signing must be constrained to ECDSA over a pre-hashed digest, the only mode an EVM signer uses.
deny contains msg if {
	some name, doc in tf.data_sources("aws_iam_policy_document")
	some stmt in doc.statement
	object.get(stmt, "effect", "Allow") == "Allow"
	"kms:Sign" in stmt.actions
	some required in ["kms:SigningAlgorithm", "kms:MessageType"]
	not tf.has_condition(stmt, required)
	msg := sprintf("data.aws_iam_policy_document.%s (sid %q): kms:Sign must be constrained by a %s condition", [name, object.get(stmt, "sid", "<none>"), required])
}

# Wildcard KMS grants are never needed for this workload.
deny contains msg if {
	some name, doc in tf.data_sources("aws_iam_policy_document")
	some stmt in doc.statement
	object.get(stmt, "effect", "Allow") == "Allow"
	some action in stmt.actions
	action in {"*", "kms:*"}
	msg := sprintf("data.aws_iam_policy_document.%s (sid %q): grants %q; enumerate actions explicitly", [name, object.get(stmt, "sid", "<none>"), action])
}

prevent_destroy(key) if {
	some lc in key.lifecycle
	lc.prevent_destroy == true
}
