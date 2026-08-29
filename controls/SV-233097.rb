control 'SV-233097' do
 title 'The container platform must enforce 24 hours (one day) as the minimum password
 lifetime.'
 desc "Enforcing a minimum password lifetime helps prevent
 repeated password changes to defeat the password reuse or history enforcement
 requirement. Restricting this setting limits the user's ability to change their
 password. Passwords need to be changed at specific policy-based intervals; however,
 if the application allows the user to immediately and continually change their
 password, then the password could be repeatedly changed in a short period of time to
 defeat the organization's policy regarding password
 reuse."
 desc 'check', 'Review the container platform configuration to determine if it
 enforces 24 hours/1 day as the minimum password lifetime. If the container
 platform does not enforce 24 hours/1 day as the minimum password lifetime, this
 is a finding.'
 desc 'fix', 'Configure the container platform to enforce 24
 hours/1 day as the minimum password lifetime.'
 impact 0.5
 tag check_id: 'C-36033r600778_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233097'
 tag rid: 'SV-233097r981862_rule'
 tag stig_id: 'SRG-APP-000173-CTR-000445'
 tag gtitle: 'SRG-APP-000173'
 tag fix_id: 'F-36001r600779_fix'
 tag 'documentable'
 tag cci: ['CCI-004066']
 tag nist: ['IA-5 (1) (h)']
 tag nist_r4: ['IA-5 (1)']
 tag ksi:  ['KSI-IAM-APM']
 tag implementation_status: 'inherited'
 tag inherited_from: 'aws-shared-responsibility'

 # AWS IAM has no minimum-password-age control; password lifecycle internals are AWS-managed.
 ev = input('inherited_evidence_uri', value: '')
 ev = attestation_uri(:leveraged, 'aws-container-platform-authorization', ext: 'json') if ev.to_s.empty?
 max_age = input('leveraged_evidence_max_age_days', value: 365)
 impact 0.5
 if ev.to_s.empty?
 describe 'AWS-inherited authorization evidence' do
 skip 'inherited-from-aws: IAM password-age internals are AWS-managed; set leveraged_evidence_base/inherited_evidence_uri or supply a SAF attestation.'
 end
 else
 doc = document_attestation(ev, max_age_days: max_age)
 describe "AWS authorization evidence (#{ev})" do
 it('exists') { expect(doc.exists?).to eq(true) }
 it('current') { expect(doc.current?(max_age)).to eq(true) }
 end
 end
end
