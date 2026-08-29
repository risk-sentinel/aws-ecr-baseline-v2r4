control 'SV-233077' do
 title 'The container platform must uniquely identify and authenticate processes acting
 on behalf of the users.'
 desc 'The container platform will instantiate a container
 image and use the user privileges given to the user used to execute the container.
 To ensure accountability and prevent unauthenticated access to containers, the user
 the container is using to execute must be uniquely identified and authenticated to
 prevent potential misuse and compromise of the
 system.'
 desc 'check', 'Review the container platform configuration to determine if processes
 acting on behalf of users are uniquely identified and authenticated. If
 processes acting on behalf of users are not uniquely identified or are not
 authenticated, this is a finding.'
 desc 'fix', 'Configure the container platform to uniquely
 identify and authenticate processes acting on behalf of users.'
 impact 0.5
 tag check_id: 'C-36013r600718_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233077'
 tag rid: 'SV-233077r1051115_rule'
 tag stig_id: 'SRG-APP-000148-CTR-000345'
 tag gtitle: 'SRG-APP-000148'
 tag fix_id: 'F-35981r600719_fix'
 tag 'documentable'
 tag cci: ['CCI-000764']
 tag nist: ['IA-2']
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
