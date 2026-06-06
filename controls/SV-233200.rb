control 'SV-233200' do
 title 'The container platform must prohibit the use of cached authenticators after an
 organization-defined time period.'
 desc 'If cached authentication information is out of date,
 the validity of the authentication information may be
 questionable.'
 desc 'check', 'Review the container platform configuration to determine if the
 platform is configured to prohibit the use of cached authenticators after an
 organization-defined time period. If the container platform is not configured to
 prohibit the use of cached authenticators after an organization-defined time
 period, this is a finding.'
 desc 'fix', 'Configure the container platform to prohibit the
 use of cached authenticators after an organization-defined time period.'
 impact 0.5
 tag check_id: 'C-36136r601803_chk'
 tag severity: 'medium'
 tag gid: 'V-233200'
 tag rid: 'SV-233200r961521_rule'
 tag stig_id: 'SRG-APP-000400-CTR-000960'
 tag gtitle: 'SRG-APP-000400'
 tag fix_id: 'F-36104r601088_fix'
 tag 'documentable'
 tag cci: ['CCI-002007']
 tag nist: ['IA-5 (13)']
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
