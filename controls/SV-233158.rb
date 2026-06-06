control 'SV-233158' do
 title 'The container platform must notify the system administrator (SA) and information
 system security officer (security officer) of account enabling actions.'
 desc 'Once an attacker establishes access to an
 application, the attacker often attempts to create a persistent method of
 re-establishing access. One way to accomplish this is for the attacker to simply
 enable a new or disabled account. Sending notification of account enabling events to
 the system administrator and security officer is one method for mitigating this risk. Such a
 capability greatly reduces the risk that application accessibility will be
 negatively affected for extended periods of time and provides logging that can be
 used for forensic purposes. To detect and respond to events that affect user
 accessibility and application processing, applications must notify the appropriate
 individuals so they can investigate the event. To address access requirements, many
 application developers choose to integrate their applications with enterprise-level
 authentication/access/auditing mechanisms that meet or exceed access control policy
 requirements. Such integration allows the application developer to offload those
 access control functions and focus on core application features and
 functionality.'
 desc 'check', 'Determine if the container platform is configured to notify system
 administrator and security officer of account enabling actions. If the container platform is
 not configured to notify the SA and security officer of account enabling actions, this is a
 finding.'
 desc 'fix', 'Configure the container platform to notify the SA
 and security officer of account enabling actions.'
 impact 0.5
 tag check_id: 'C-36094r981876_chk'
 tag severity: 'medium'
 tag gid: 'V-233158'
 tag rid: 'SV-233158r981878_rule'
 tag stig_id: 'SRG-APP-000320-CTR-000750'
 tag gtitle: 'SRG-APP-000320'
 tag fix_id: 'F-36062r981877_fix'
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
