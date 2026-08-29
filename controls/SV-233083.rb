control 'SV-233083' do
 title 'The container platform must ensure users are authenticated with an individual
 authenticator prior to using a group authenticator.'
 desc 'To ensure individual accountability and prevent
 unauthorized access, application users must be individually identified and
 authenticated. Individual accountability mandates that each user be uniquely
 identified. A group authenticator is a shared account or some other form of
 authentication that allows multiple unique individuals to access the application
 using a single account. If an application allows or provides for group
 authenticators, it must first individually authenticate users prior to implementing
 group authenticator functionality. Some applications may not need to provide a group
 authenticator; this is considered a matter of application design. In those instances
 where the application design includes the use of a group authenticator, this
 requirement will apply. There may also be instances when specific user actions need
 to be performed on the information system without unique user identification or
 authentication. An example of this type of access is a web server, which contains
 publicly releasable
 information.'
 desc 'check', 'Review the container platform configuration to determine if the
 container platform is configured to ensure users are authenticated with an
 individual authenticator prior to using a group authenticator. If the container
 platform is not configured to ensure users are authenticated with an individual
 authenticator prior to using a group authenticator, this is a finding.'
 desc 'fix', 'Configure the container platform to ensure users
 are authenticated with an individual authenticator prior to using a group
 authenticator.'
 impact 0.5
 tag check_id: 'C-36019r601714_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233083'
 tag rid: 'SV-233083r981849_rule'
 tag stig_id: 'SRG-APP-000153-CTR-000375'
 tag gtitle: 'SRG-APP-000153'
 tag fix_id: 'F-35987r600737_fix'
 tag 'documentable'
 tag cci: ['CCI-004045']
 tag nist: ['IA-2 (5)']
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
