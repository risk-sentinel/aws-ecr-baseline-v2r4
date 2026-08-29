control 'SV-233031' do
 title 'The container platform must enforce the limit of three consecutive invalid logon
 attempts by a user during a 15-minute time period.'
 desc 'By limiting the number of failed login attempts, the
 risk of unauthorized system access via user password guessing, otherwise known as
 brute forcing, is reduced. Limits are imposed by locking the
 account.'
 desc 'check', 'Review the container platform to determine if it is configured to
 enforce the limit of three consecutive invalid logon attempts by a user during a
 15-minute time period. If the container platform is not configured to enforce
 the limit of three consecutive invalid logon attempts by a user during a
 15-minute time period, this is a finding.'
 desc 'fix', 'Configure the container platform to enforce the
 limit of three consecutive invalid logon attempts by a user during a 15-minute time
 period.'
 impact 0.5
 tag check_id: 'C-35967r601606_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233031'
 tag rid: 'SV-233031r960840_rule'
 tag stig_id: 'SRG-APP-000065-CTR-000115'
 tag gtitle: 'SRG-APP-000065'
 tag fix_id: 'F-35935r600581_fix'
 tag 'documentable'
 tag cci: ['CCI-000044']
 tag nist: ['AC-7 a']
 tag nist_r4: ['AC-7 a']
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
