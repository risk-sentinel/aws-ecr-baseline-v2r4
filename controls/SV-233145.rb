control 'SV-233145' do
 title 'The container platform must notify system administrators and security officer for account
 disabling actions.'
 desc 'When application accounts are disabled, user
 accessibility is affected. Accounts are utilized for identifying individual users or
 for identifying the application processes themselves. Sending notification of
 account disabling events to the system administrator and security officer is one method for
 mitigating this risk. Such a capability greatly reduces the risk that application
 accessibility will be negatively affected for extended periods of time and provides
 logging that can be used for forensic purposes. To address access requirements, many
 operating systems can be integrated with enterprise-level
 authentication/access/auditing mechanisms that meet or exceed access control policy
 requirements.'
 desc 'check', 'Review the container platform configuration to determine if system
 administrators and security officer are notified when accounts are disabled. If system
 administrators and security officer are not notified, this is a finding.'
 desc 'fix', 'Configure the container platform to notify system
 administrators and security officer when accounts are disabled.'
 impact 0.5
 tag check_id: 'C-36081r600922_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233145'
 tag rid: 'SV-233145r981873_rule'
 tag stig_id: 'SRG-APP-000293-CTR-000685'
 tag gtitle: 'SRG-APP-000293'
 tag fix_id: 'F-36049r600923_fix'
 tag 'documentable'
 tag cci: ['CCI-000015']
 tag nist: ['AC-2 (1)']
 tag implementation_status: 'alternative'
 tag attestation_category: 'operational'

 impact 0.5
 describe 'operational/governance control (SAF attestation)' do
 skip 'organizational/operational control (alerting, governance policy, or password-breach tooling) — not API-assertable; supply a SAF attestation.'
 end
end
