control 'SV-263586' do
 title 'The container platform must disable accounts when the accounts are no longer
 associated to a user.'
 desc 'Disabling expired, inactive, or otherwise anomalous
 accounts supports the concepts of least privilege and least functionality which
 reduce the attack surface of the
 system.'
 desc 'check', 'Verify the container platform is configured to disable accounts when
 the accounts are no longer associated to a user. If the container platform is
 not configured to disable accounts when the accounts are no longer associated to
 a user, this is a finding.'
 desc 'fix', 'Configure the container platform to disable
 accounts when the accounts are no longer associated to a user.'
 impact 0.5
 tag check_id: 'C-67486r982452_chk'
 tag severity: 'medium'
 tag gid: 'V-263586'
 tag rid: 'SV-263586r982453_rule'
 tag stig_id: 'SRG-APP-000705-CTR-000110'
 tag gtitle: 'SRG-APP-000705'
 tag fix_id: 'F-67394r981897_fix'
 tag 'documentable'
 tag cci: ['CCI-003628']
 tag nist: ['AC-2 (3) (b)']
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
