package pipeline_forbidden
required_steps = ["Create_Change","Check_Approval"]
included_orgs = ["default","org_id"]
excluded_orgs = ["org","org2"]
excluded_services = ["samplek8s","samplek8s","samplehelm","account.samplehelm","account.samplek8s"]

deny[sprintf("Deployments to '%s' require approval.  Stage '%s' is missing required step '%s' service '%s'", [all_stages[_].spec.infrastructure.environment.type, all_stages[_].name,required_steps[_],all_stages[_].spec.service.service.identifier])] {
    input.metadata.projectMetadata.orgIdentifier == included_orgs[_]
    input.metadata.projectMetadata.orgIdentifier != excluded_orgs[_]
    parallel_stages := [s | s = input.pipeline.stages[_].parallel[_].stage]
    s_stages := [s | s =  input.pipeline.stages[_].stage]
    all_stages := array.concat(parallel_stages,s_stages) # combine sequential and parallel in a single array
    all_stages[_].type == "Deployment"
    all_stages[_].spec.infrastructure.environment.type == "Production"
    all_stages[i].spec.service.service.identifier != excluded_services[i] #filter excluded services
    parallel_steps := [s | s = all_stages[_].spec.execution.steps[_].parallel[_].step.identifier]
    s_steps := [s | s = all_stages[_].spec.execution.steps[_].step.identifier]
    s_sg_steps := [s | s = all_stages[_].spec.execution.steps[_].stepGroup[_].step.identifier]
    parallel_sg := [s | s = all_stages[_].spec.execution.steps[_].parallel[_].stepGroup.steps[_].step.identifier]
    sg_steps := array.concat(s_sg_steps,parallel_sg)
    ps_steps := array.concat(parallel_steps,s_steps) # combine sequential and parallel in a single array
    all_steps := array.concat(ps_steps,sg_steps) #combined sequential, parallel and steGroup steps
    req_step := required_steps[_]
    a_step := all_steps[_]
    not contains(a_step, req_step)
}
