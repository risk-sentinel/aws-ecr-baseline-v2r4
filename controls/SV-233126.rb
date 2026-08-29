control 'SV-233126' do
 title 'The container platform must never automatically remove or disable emergency
 accounts.'
 desc 'Emergency accounts are administrator accounts that
 are established in response to crisis situations where the need for rapid account
 activation is required. Therefore, emergency account activation may bypass normal
 account authorization processes. If these accounts are automatically disabled,
 system maintenance during emergencies may not be possible, thus adversely affecting
 system availability. Emergency accounts are different from infrequently used
 accounts (i.e., local logon accounts used by system administrators when network or
 normal logon/access is not available). Infrequently used accounts also remain
 available and are not subject to automatic termination dates. However, an emergency
 account is normally a different account that is created for use by vendors or system
 maintainers. To address access requirements, many application developers choose to
 integrate their applications with enterprise-level authentication/access mechanisms
 that meet or exceed access control policy requirements. Such integration allows the
 application developer to off-load those access control functions and focus on core
 application features and
 functionality.'
 desc 'check', 'Review the container platform to determine if emergency accounts are
 automatically removed or disabled. If emergency accounts are automatically
 removed or disabled, this is a finding.'
 desc 'fix', 'Configure the container platform to never remove or
 disable emergency accounts.'
 impact 0.5
 tag check_id: 'C-36062r600865_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233126'
 tag rid: 'SV-233126r971528_rule'
 tag stig_id: 'SRG-APP-000234-CTR-000590'
 tag gtitle: 'SRG-APP-000234'
 tag fix_id: 'F-36030r600866_fix'
 tag 'documentable'
 tag cci: ['CCI-001682']
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
