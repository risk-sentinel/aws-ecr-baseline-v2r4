control 'SV-233101' do
 title 'The container platform must map the authenticated identity to the individual user
 or group account for PKI-based authentication.'
 desc 'The container platform and its components may require
 authentication before use. When the authentication is PKI-based, the container
 platform or component must map the certificate to a user account. If the certificate
 is not mapped to a user account, the ability to determine the identity of the
 individual user or group will not be available for forensic
 analysis.'
 desc 'check', 'Review documentation and configuration to ensure the container
 platform provides a PKI integration capability that meets organization PKI infrastructure
 requirements. If the container platform is not configured to meet this
 requirement, this is a finding.'
 desc 'fix', 'Configure the container platform to utilize the organization
 Enterprise PKI infrastructure.'
 impact 0.5
 tag check_id: 'C-36037r600790_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233101'
 tag rid: 'SV-233101r961044_rule'
 tag stig_id: 'SRG-APP-000177-CTR-000465'
 tag gtitle: 'SRG-APP-000177'
 tag fix_id: 'F-36005r600791_fix'
 tag 'documentable'
 tag cci: ['CCI-000187']
 tag nist: ['IA-5 (2) (a) (2)']
 tag nist_r4: ['IA-5 (2) (c)']
 tag implementation_status: 'inherited'
 tag inherited_from: 'aws-shared-responsibility'

 # AWS-managed: IAM identity internals / Fargate runtime / platform config (the cloud-provider authorization).
 ev = input('inherited_evidence_uri', value: '')
 ev = attestation_uri(:leveraged, 'aws-container-platform-authorization', ext: 'json') if ev.to_s.empty?
 max_age = input('leveraged_evidence_max_age_days', value: 365)
 impact 0.5
 if ev.to_s.empty?
 describe 'AWS-inherited authorization evidence' do
 skip 'inherited-from-aws: AWS-managed layer; set leveraged_evidence_base/inherited_evidence_uri to the cloud-provider authorization manifest, or supply a SAF attestation.'
 end
 else
 doc = document_attestation(ev, max_age_days: max_age)
 describe "AWS authorization evidence (#{ev})" do
 it('exists') { expect(doc.exists?).to eq(true) }
 it('current') { expect(doc.current?(max_age)).to eq(true) }
 end
 end
end
