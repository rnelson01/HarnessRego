package pipeline_forbidden
required_steps = ["Create_Change","Check_Approval"] #stepIDs
included_orgs = ["default","org_id"] #orgIds
excluded_orgs = ["org","org2"] #orgIDs
excluded_services = ["samplek8s","samplek8s","samplehelm","account.samplehelm","account.samplek8s"] #serviceIDs

deny[sprintf("Stage '%s' is missing required step '%s'", [all_stages[_].name,required_steps[_]])] {
    input.metadata.projectMetadata.orgIdentifier == included_orgs[_] #filter only included org list
    input.metadata.projectMetadata.orgIdentifier != excluded_orgs[_] #filter excluded orgs
    parallel_stages := [s | s = input.pipeline.stages[_].parallel[_].stage] #gather all stages 1
    s_stages := [s | s =  input.pipeline.stages[_].stage] #gather all stages 2
    all_stages := array.concat(parallel_stages,s_stages) # combine sequential and parallel in a single array
    all_stages[_].type == "Deployment"
    all_stages[_].spec.infrastructure.environment.type == "Production"
    all_stages[i].spec.service.service.identifier != excluded_services[i] #filter excluded services
    parallel_steps := [s | s = all_stages[_].spec.execution.steps[_].parallel[_].step.identifier] #gather steps 1
    s_steps := [s | s = all_stages[_].spec.execution.steps[_].step.identifier] #gather steps 2
    s_sg_steps := [s | s = all_stages[_].spec.execution.steps[_].stepGroup[_].step.identifier] #gather steps 3
    parallel_sg := [s | s = all_stages[_].spec.execution.steps[_].parallel[_].stepGroup.steps[_].step.identifier] #gather steps 4
    sg_steps := array.concat(s_sg_steps,parallel_sg)
    ps_steps := array.concat(parallel_steps,s_steps) # combine sequential and parallel in a single array
    all_steps := array.concat(ps_steps,sg_steps) #combined sequential, parallel and steGroup steps
    req_step := required_steps[_]
    a_step := all_steps[_]
    not contains(a_step, req_step)
}
