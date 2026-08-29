control 'SV-233075' do
 title 'The container platform must uniquely identify and authenticate users.'
 desc 'The container platform requires user accounts to
 perform container platform tasks. These tasks may pertain to the overall container
 platform or may be component-specific, thus requiring users to authenticate against
 those specific components. To ensure accountability and prevent unauthenticated
 access, users must be identified and authenticated to prevent potential misuse and
 compromise of the
 system.'
 desc 'check', 'Review the container platform configuration to determine if users are
 uniquely identified and authenticated. If users are not uniquely identified or
 are not authenticated, this is a finding.'
 desc 'fix', 'Configure the container platform to uniquely
 identify and authenticate users.'
 impact 0.5
 tag check_id: 'C-36011r600712_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233075'
 tag rid: 'SV-233075r1051115_rule'
 tag stig_id: 'SRG-APP-000148-CTR-000335'
 tag gtitle: 'SRG-APP-000148'
 tag fix_id: 'F-35979r600713_fix'
 tag 'documentable'
 tag cci: ['CCI-000764']
 tag nist: ['IA-2']
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
