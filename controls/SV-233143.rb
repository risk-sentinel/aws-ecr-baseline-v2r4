control 'SV-233143' do
 title 'The container platform must notify system administrators (SAs) and the
 information system security officer (security officer) when accounts are created.'
 desc 'Once an attacker establishes access to an
 application, the attacker often attempts to create a persistent method of
 re-establishing access. One way to accomplish this is for the attacker to simply
 create a new account. Sending notification of account creation events to the SA and
 security officer is one method for mitigating this risk. To address access requirements, many
 application developers choose to integrate their applications with enterprise-level
 authentication/access/auditing mechanisms that meet or exceed access control policy
 requirements. Such integration allows the application developer to offload those
 access control functions and focus on core application features and
 functionality.'
 desc 'check', 'Review the container platform configuration to determine if system
 administrators and security officer are notified when accounts are created. If SAs and security officer
 are not notified, this is a finding.'
 desc 'fix', 'Configure the container platform to notify SAs and
 security officer when accounts are created.'
 impact 0.5
 tag check_id: 'C-36079r981869_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233143'
 tag rid: 'SV-233143r981871_rule'
 tag stig_id: 'SRG-APP-000291-CTR-000675'
 tag gtitle: 'SRG-APP-000291'
 tag fix_id: 'F-36047r981870_fix'
 tag 'documentable'
 tag cci: ['CCI-000015']
 tag nist: ['AC-2 (1)']
 tag nist_r4: ['AC-2 (1)']
 tag implementation_status: 'alternative'
 tag attestation_category: 'operational'

 impact 0.5
 describe 'operational/governance control (SAF attestation)' do
 skip 'organizational/operational control (alerting, governance policy, or password-breach tooling) — not API-assertable; supply a SAF attestation.'
 end
end
