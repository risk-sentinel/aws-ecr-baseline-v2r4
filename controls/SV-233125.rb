control 'SV-233125' do
 title 'The container platform runtime must isolate security functions from non-security
 functions.'
 desc 'The container platform runtime must be configured to
 isolate those services used for security functions from those used for non-security
 functions. This separation can be performed using environment variables, labels,
 network segregation, and kernel
 groups.'
 desc 'check', 'Verify container platform runtime configuration settings to determine
 whether container services used for security functions are located in an
 isolated security function such as a separate environment variables, labels,
 network segregation, and kernel groups. If security-related functions are not
 separate, this is a finding.'
 desc 'fix', 'Configure the container platform runtime to isolate
 security functions from non-security functions.'
 impact 0.5
 tag check_id: 'C-36061r601750_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233125'
 tag rid: 'SV-233125r961131_rule'
 tag stig_id: 'SRG-APP-000233-CTR-000585'
 tag gtitle: 'SRG-APP-000233'
 tag fix_id: 'F-36029r600863_fix'
 tag 'documentable'
 tag cci: ['CCI-001084']
 tag nist: ['SC-3']
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
