package pipeline_template



deny[msg] {
	# Find all parallel and sequential stages 
	parallel_stages := [s | s = input.pipeline.stages[_].parallel[_].stage.template.templateRef]
    s_stages := [s | s =  input.pipeline.stages[_].stage.template.templateRef]
    
    # combine sequential and parallel in a single array
    all_stages := array.concat(parallel_stages,s_stages)

    # for each required template
    required_template := required_templates[_]
    # ... where required template is not present 
	not contains(all_stages, required_template)

	# Show a human-friendly error message
	msg := sprintf("Pipeline does not contain required template '%s'", [required_template])
}

required_templates = ["account.Security_Approval_Template", "account.security_scans"]

contains(arr, elem) {
	arr[_] = elem
}
