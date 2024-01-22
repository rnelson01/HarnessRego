package pipeline_forbidden

# Deny pipelines that include forbidden commands tm Ryan Nelson ;/
deny[sprintf("Pipeline must include step template '%s' ", [required_templates[i]])] {
    parallel_stages := [s | s = input.pipeline.stages[_].parallel[_].stage]
    s_stages := [s | s =  input.pipeline.stages[_].stage]
    all_stages := array.concat(parallel_stages,s_stages) # combine sequential and parallel in a single array
    parallel_steps := [s | s = all_stages[_].spec.execution.steps[_].parallel[_].step.template.templateRef]
    s_steps := [s | s = all_stages[_].spec.execution.steps[_].step.template.templateRef]
    all_steps := array.concat(parallel_steps,s_steps) # combine sequential and parallel in a single array
    req_template := required_templates[_]
    a_step := all_steps[_]
    not contains(a_step, req_template)
}
required_templates = ["account.aqua", "account.sonar"]
