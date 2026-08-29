control 'SV-233021' do
 title 'The container platform must automatically disable accounts after a 35-day period
 of account inactivity.'
 desc 'Attackers that are able to exploit an inactive
 account can potentially obtain and maintain undetected access to an application.
 Owners of inactive accounts will not notice if unauthorized access to their user
 account has been obtained. Applications need to track periods of user inactivity and
 disable accounts after 35 days of inactivity. Such a process greatly reduces the
 risk that accounts will be hijacked, leading to a data compromise. To address access
 requirements, many application developers choose to integrate their applications
 with enterprise-level authentication/access mechanisms that meet or exceed access
 control policy requirements. Such integration allows the application developer to
 off-load those access control functions and focus on core application features and
 functionality. This policy does not apply to either emergency accounts or
 infrequently used accounts. Infrequently used accounts are local login administrator
 accounts used by system administrators when network or normal logon/access is not
 available. Emergency accounts are administrator accounts created in response to
 crisis
 situations.'
 desc 'check', 'Determine if the container platform automatically disables accounts
 after a 35-day period of account inactivity. If the container platform does not
 automatically disable accounts after a 35-day period of account inactivity, this
 is a finding.'
 desc 'fix', 'Configure the container platform to automatically
 disable accounts after a 35-day period of account inactivity.'
 impact 0.5
 tag check_id: 'C-35957r601888_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233021'
 tag rid: 'SV-233021r960774_rule'
 tag stig_id: 'SRG-APP-000025-CTR-000065'
 tag gtitle: 'SRG-APP-000025'
 tag fix_id: 'F-35925r601889_fix'
 tag 'documentable'
 tag cci: ['CCI-000017']
 tag nist: ['AC-2 (3) (d)']
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
