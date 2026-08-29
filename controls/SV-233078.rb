control 'SV-233078' do
 title 'The container platform application program interface (API) must uniquely identify
 and authenticate processes acting on behalf of the users.'
 desc "The container platform API can be used to perform any
 task within the platform. Often, the API is used to create tasks that perform some
 kind of maintenance task and run without user interaction. To guarantee the task is
 authorized, it is important to authenticate the task. These tasks, even though
 executed without user intervention, run on behalf of a user and must run with the
 user's authorization. If tasks are allowed to be created without authentication,
 users could bypass authentication and authorization mechanisms put in place for user
 interfaces. This could lead to users gaining greater access than given to the user
 putting the container platform into a compromised
 state."
 desc 'check', 'Review the container platform API configuration to determine if
 processes acting on behalf of users are uniquely identified and authenticated.
 If processes acting on behalf of users are not uniquely identified or are not
 authenticated, this is a finding.'
 desc 'fix', 'Configure the container platform API to uniquely
 identify and authenticate processes acting on behalf of users.'
 impact 0.5
 tag check_id: 'C-36014r601708_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233078'
 tag rid: 'SV-233078r1051115_rule'
 tag stig_id: 'SRG-APP-000148-CTR-000350'
 tag gtitle: 'SRG-APP-000148'
 tag fix_id: 'F-35982r600722_fix'
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
