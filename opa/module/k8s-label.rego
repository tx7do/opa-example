package kubernetes.validating.existence

deny[msg] {
	not input.request.object.metadata.labels.domain
	msg := "Every resource must have a domain label"
}


deny[msg] {
	value := input.request.object.metadata.labels.domain
	not startswith(value, "moelove-")
	msg := sprintf("domain label must start with `moelove-`; found `%v`", [value])
}
