# Helpers for querying Terraform HCL parsed by `conftest test --parser hcl2 --combine`.
# With --combine, `input` is an array of {"path": ..., "contents": <parsed HCL>}.
package lib.terraform

docs contains file.contents if {
	some file in input
}

# resources("aws_kms_key") -> {"<name>": <block>}
resources(rtype) := {name: block |
	some doc in docs
	some name, blocks in doc.resource[rtype]
	some block in blocks
}

# data_sources("aws_iam_policy_document") -> {"<name>": <block>}
data_sources(dtype) := {name: block |
	some doc in docs
	some name, blocks in doc.data[dtype]
	some block in blocks
}

variables := {name: block |
	some doc in docs
	some name, blocks in doc.variable
	some block in blocks
}

locals_map := {name: value |
	some doc in docs
	some block in doc.locals
	some name, value in block
}

local_refs := {sprintf("${local.%s}", [name]): value |
	some name, value in locals_map
	is_string(value)
}

# Expand "${local.foo}" references (one level) so policies can inspect what an expression resolves to.
resolve(s) := strings.replace_n(local_refs, s)

has_condition(stmt, variable) if {
	some cond in stmt.condition
	cond.variable == variable
}
