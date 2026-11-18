# Guardrails for GitHub Actions OIDC trust policies.
# A loose `sub` condition (wildcards, StringLike, or a pull_request subject) lets ANY workflow run, including
# one from a fork or a feature branch, assume the role that can sign mainnet transactions.
package terraform.github_oidc

import data.lib.terraform as tf

oidc_host := "token.actions.githubusercontent.com"

trust_statements contains [name, stmt] if {
	some name, doc in tf.data_sources("aws_iam_policy_document")
	some stmt in doc.statement
	"sts:AssumeRoleWithWebIdentity" in stmt.actions
}

sub_conditions(stmt) := [cond |
	some cond in stmt.condition
	endswith(tf.resolve(cond.variable), ":sub")
]

deny contains msg if {
	some [name, stmt] in trust_statements
	count(sub_conditions(stmt)) == 0
	msg := sprintf("data.aws_iam_policy_document.%s: OIDC trust must pin %s:sub", [name, oidc_host])
}

deny contains msg if {
	some [name, stmt] in trust_statements
	not has_audience(stmt)
	msg := sprintf("data.aws_iam_policy_document.%s: OIDC trust must require %s:aud = sts.amazonaws.com", [name, oidc_host])
}

deny contains msg if {
	some [name, stmt] in trust_statements
	some cond in sub_conditions(stmt)
	cond.test != "StringEquals"
	msg := sprintf("data.aws_iam_policy_document.%s: sub condition uses %q; only exact StringEquals matching is allowed", [name, cond.test])
}

deny contains msg if {
	some [name, stmt] in trust_statements
	some cond in sub_conditions(stmt)
	some raw in cond.values
	subject := tf.resolve(raw)
	not allowed_subject(subject)
	msg := sprintf("data.aws_iam_policy_document.%s: sub %q must be repo:<owner>/<repo>:environment:<env> or :ref:refs/heads/main, with no wildcards", [name, subject])
}

allowed_subject(subject) if {
	startswith(subject, "repo:")
	not contains(subject, "*")
	not contains(subject, "?")
	contains(subject, ":environment:")
}

allowed_subject(subject) if {
	startswith(subject, "repo:")
	not contains(subject, "*")
	not contains(subject, "?")
	endswith(subject, ":ref:refs/heads/main")
}

has_audience(stmt) if {
	some cond in stmt.condition
	endswith(tf.resolve(cond.variable), ":aud")
	cond.test == "StringEquals"
	cond.values == ["sts.amazonaws.com"]
}
