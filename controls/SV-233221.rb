control 'SV-233221' do
 title 'The container platform runtime must maintain separate execution domains for each
 container by assigning each container a separate address space.'
 desc 'Container namespace access is limited upon runtime
 execution. Each container is a distinct process so that communication between
 containers is performed in a manner controlled through security policies that limits
 the communication so one container cannot modify another container. Different groups
 of containers with different security needs should be deployed in separate
 namespaces as a first level of isolation. Namespaces are a key boundary for network
 policies, orchestrator access control restrictions, and other important security
 controls. Separating workloads into namespaces can help contain attacks and limit
 the impact of mistakes or destructive actions by authorized users. This requirement
 also applies to Zero Trust
 initiatives.'
 desc 'check', 'Review container platform runtime documentation and configuration is
 maintaining a separate execution domain for each executing process. Different
 groups of applications, and services with different security needs, should be
 deployed in separate namespaces as a first level of isolation. If container
 platform runtime is not configured to execute processes in separate domains and
 namespaces, this is a finding. If namespaces use defaults, this is a finding.'
 desc 'fix', 'Deploy a container platform runtime capable of
 maintaining a separate execution domain and namespace for each executing process.
 Create a namespace for each containers, defining them as logical groups.'
 impact 0.5
 tag check_id: 'C-36157r601813_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233221'
 tag rid: 'SV-233221r1137646_rule'
 tag stig_id: 'SRG-APP-000431-CTR-001065'
 tag gtitle: 'SRG-APP-000431'
 tag fix_id: 'F-36125r601151_fix'
 tag 'documentable'
 tag cci: ['CCI-002530']
 tag nist: ['SC-39']
 tag implementation_status: 'inherited'
 tag inherited_from: 'aws-shared-responsibility'

 # AWS-managed container-platform layer (runtime/host/control-plane/crypto-module/audit-
 # infra). Evidence = the leveraged the cloud-provider authorization manifest; Skip (not a
 # vacuous pass) until the consumer configures leveraged_evidence_base/inherited_evidence_uri.
 ev = input('inherited_evidence_uri', value: '')
 ev = attestation_uri(:leveraged, 'aws-container-platform-authorization', ext: 'json') if ev.to_s.empty?
 max_age = input('leveraged_evidence_max_age_days', value: 365)
 impact 0.5
 if ev.to_s.empty?
 describe 'AWS-inherited authorization evidence' do
 skip 'inherited-from-aws: AWS-managed layer; set leveraged_evidence_base / inherited_evidence_uri to the cloud-provider authorization manifest, or supply a SAF attestation.'
 end
 else
 doc = document_attestation(ev, max_age_days: max_age)
 describe "AWS authorization evidence (#{ev})" do
 it('exists') { expect(doc.exists?).to eq(true) }
 it('current') { expect(doc.current?(max_age)).to eq(true) }
 end
 end
end
