control 'SV-233076' do
 title 'The container platform application program interface (API) must uniquely identify
 and authenticate users.'
 desc 'The container platform requires user accounts to
 perform container platform tasks. These tasks are often performed through the
 container platform API. Protecting the API from users who are not authorized or
 authenticated is essential to keep the container platform stable. Protection of
 platform and application data and enhances the protections put in place for
 Denial-of Service (DoS)
 attacks.'
 desc 'check', 'Review the container platform configuration to determine if users are
 uniquely identified and authenticated before the API is executed. If users are
 not uniquely identified or are not authenticated, this is a finding.'
 desc 'fix', 'Configure the container platform to uniquely
 identify and authenticate users before container platform API access.'
 impact 0.5
 tag check_id: 'C-36012r600715_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233076'
 tag rid: 'SV-233076r1051115_rule'
 tag stig_id: 'SRG-APP-000148-CTR-000340'
 tag gtitle: 'SRG-APP-000148'
 tag fix_id: 'F-35980r600716_fix'
 tag 'documentable'
 tag cci: ['CCI-000764']
 tag nist: ['IA-2']
 tag ksi:  ['KSI-IAM-APM', 'KSI-IAM-ELP']
 tag nist_r4: ['IA-2']
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
