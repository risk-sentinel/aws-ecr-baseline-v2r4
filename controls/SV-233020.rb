control 'SV-233020' do
 title 'The container platform must automatically remove or disable temporary user
 accounts after 72 hours.'
 desc 'If temporary user accounts remain active when no
 longer needed or for an excessive period, these accounts may be used to gain
 unauthorized access. To mitigate this risk, automated termination of all temporary
 user accounts must be set upon account creation. Temporary user accounts are
 established as part of normal account activation procedures when there is a need for
 short-term accounts without the demand for immediacy in account activation. If
 temporary user accounts are used, the application must be configured to
 automatically terminate these types of accounts after a organization-defined period of 72
 hours. To address access requirements, many application developers choose to
 integrate their applications with enterprise-level authentication/access mechanisms
 that meet or exceed access control policy requirements. Such integration allows the
 application developer to off-load those access control functions and focus on core
 application features and
 functionality.'
 desc 'check', 'Review the container platform configuration to determine if temporary
 user accounts are automatically removed or disabled after 72 hours. If temporary
 user accounts are not automatically removed or disabled after 72 hours, this is
 a finding.'
 desc 'fix', 'Configure the container platform to automatically
 remove or disable temporary user accounts after 72 hours.'
 impact 0.5
 tag check_id: 'C-35956r600547_chk'
 tag severity: 'medium'
 tag gid: 'V-233020'
 tag rid: 'SV-233020r960771_rule'
 tag stig_id: 'SRG-APP-000024-CTR-000060'
 tag gtitle: 'SRG-APP-000024'
 tag fix_id: 'F-35924r600548_fix'
 tag 'documentable'
 tag cci: ['CCI-000016']
 tag nist: ['AC-2 (2)']
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
