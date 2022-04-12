ovs-vsctl -- --id=@ft create Flow_Table flow_limit=500 overflow_policy=refuse -- set Bridge s1 flow_tables=0=@ft
ovs-vsctl -- --id=@ft create Flow_Table flow_limit=500 overflow_policy=refuse -- set Bridge s2 flow_tables=0=@ft
ovs-vsctl -- --id=@ft create Flow_Table flow_limit=500 overflow_policy=refuse -- set Bridge s3 flow_tables=0=@ft
ovs-vsctl -- --id=@ft create Flow_Table flow_limit=500 overflow_policy=refuse -- set Bridge s4 flow_tables=0=@ft
ovs-vsctl -- --id=@ft create Flow_Table flow_limit=500 overflow_policy=refuse -- set Bridge s5 flow_tables=0=@ft
