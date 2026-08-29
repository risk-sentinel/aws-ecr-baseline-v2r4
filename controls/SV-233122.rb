control 'SV-233122' do
 title 'The container platform runtime must fail to a secure state if system
 initialization fails, shutdown fails, or aborts fail.'
 desc 'The container platform offers services for container
 image orchestration and services for users. If any of these services were to fail
 into an insecure state, security measures for user and data separation and image
 instantiation could become absent. In addition, audit log protections could be
 relaxed allowing for investigation of what occurred could be lost. To protect
 services and data, it is important for the container platform to fail to a secure
 state if the container platform registry initialization fails, shutdown fails, or
 aborts
 fail.'
 desc 'check', 'Review documentation and configuration to determine if the container
 platform runtime fails to a secure state if system initialization fails,
 shutdown fails, or aborts fail. If the container platform runtime cannot be
 configured to fail securely, this is a finding.'
 desc 'fix', 'Configure the container platform runtime to fail to
 a secure state if system initialization fails, shutdown fails, or aborts fail.'
 impact 0.5
 tag check_id: 'C-36058r601746_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233122'
 tag rid: 'SV-233122r961122_rule'
 tag stig_id: 'SRG-APP-000225-CTR-000570'
 tag gtitle: 'SRG-APP-000225'
 tag fix_id: 'F-36026r600854_fix'
 tag 'documentable'
 tag cci: ['CCI-001190']
 tag nist: ['SC-24']
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
