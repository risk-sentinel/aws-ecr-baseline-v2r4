control 'SV-233270' do
 title 'The container runtime must generate audit records for all container execution,
 shutdown, restart events, and program initiations.'
 desc 'The container runtime must generate audit records
 that are specific to the security and mission needs of the organization. Without
 audit record, it would be difficult to establish, correlate, and investigate events
 relating to an
 incident.'
 desc 'check', 'Review the container runtime configuration to validate audit record
 generation for container execution, shutdown, and restart events. If the
 container runtime does not generate records for container execution, shutdown
 and restart events, this is a finding.'
 desc 'fix', 'Configure the container runtime to generate audit
 records for container execution, shutdown, and restart events.'
 impact 0.5
 tag check_id: 'C-36206r601847_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233270'
 tag rid: 'SV-233270r961845_rule'
 tag stig_id: 'SRG-APP-000510-CTR-001310'
 tag gtitle: 'SRG-APP-000510'
 tag fix_id: 'F-36174r601298_fix'
 tag 'documentable'
 tag cci: ['CCI-000172']
 tag nist: ['AU-12 c']
 tag ksi:  ['KSI-MLA-LET']
 tag nist_r4: ['AU-12 c']
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
