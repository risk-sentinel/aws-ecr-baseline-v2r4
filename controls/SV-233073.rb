control 'SV-233073' do
 title 'The container platform runtime must enforce ports, protocols, and services that
 adhere to the approved ports, protocols, and services (PPS) baseline.'
 desc 'Ports, protocols, and services within the container
 platform runtime must be controlled and conform to the approved ports, protocols, and services (PPS) baseline. Those ports,
 protocols, and services that fall outside the approved ports, protocols, and services (PPS) baseline must be blocked by the
 runtime. Instructions on the ports, protocols, and services (PPS) policy can be found in organization Instruction 8551.01
 Policy.'
 desc 'check', 'Review the container platform documentation and deployment
 configuration to determine which ports and protocols are enabled. Verify the
 ports and protocols being used are not prohibited by approved ports, protocols, and services (PPS) baseline in accordance to
 organization Instruction 8551.01 Policy and are necessary for the operations and
 applications. If any of the ports or protocols is prohibited or not necessary
 for the operation, this is a finding.'
 desc 'fix', 'Configure the container platform to disable any
 ports or protocols that are prohibited by the approved ports, protocols, and services (PPS) baseline and not necessary for the
 operation.'
 impact 0.5
 tag check_id: 'C-36009r601891_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233073'
 tag rid: 'SV-233073r1043177_rule'
 tag stig_id: 'SRG-APP-000142-CTR-000325'
 tag gtitle: 'SRG-APP-000142'
 tag fix_id: 'F-35977r600707_fix'
 tag 'documentable'
 tag cci: ['CCI-000382']
 tag nist: ['CM-7 b']
 tag nist_r4: ['CM-7 b']
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
