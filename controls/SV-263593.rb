control 'SV-263593' do
 title 'The container platform must for password-based authentication, update the list of
 passwords when organizational passwords are suspected to have been compromised
 directly or indirectly.'
 desc 'Password-based authentication applies to passwords
 regardless of whether they are used in single-factor or multi-factor authentication.
 Long passwords or passphrases are preferable over shorter passwords. Enforced
 composition rules provide marginal security benefits while decreasing usability.
 However, organizations may choose to establish certain rules for password generation
 (e.g., minimum character length for long passwords) under certain circumstances and
 can enforce this requirement in IA-5(1)(h). Account recovery can occur, for example,
 in situations when a password is forgotten. Cryptographically protected passwords
 include salted one-way cryptographic hashes of passwords. The list of commonly used,
 compromised, or expected passwords includes passwords obtained from previous breach
 corpuses, dictionary words, and repetitive or sequential characters. The list
 includes context-specific words, such as the name of the service, username, and
 derivatives
 thereof.'
 desc 'check', 'Verify the container platform is configured to update the list of
 passwords when organizational passwords are suspected to have been compromised
 directly or indirectly. If the container platform is not configured to update
 the list of passwords when organizational passwords are suspected to have been
 compromised directly or indirectly, this is a finding.'
 desc 'fix', 'Configure the container platform to update the list
 of passwords when organizational passwords are suspected to have been compromised
 directly or indirectly.'
 impact 0.5
 tag check_id: 'C-67493r982460_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-263593'
 tag rid: 'SV-263593r982461_rule'
 tag stig_id: 'SRG-APP-000840-CTR-000210'
 tag gtitle: 'SRG-APP-000840'
 tag fix_id: 'F-67401r981918_fix'
 tag 'documentable'
 tag cci: ['CCI-004060']
 tag nist: ['IA-5 (1) (a)']
 tag implementation_status: 'alternative'
 tag attestation_category: 'operational'

 impact 0.5
 describe 'operational/governance control (SAF attestation)' do
 skip 'organizational/operational control (alerting, governance policy, or password-breach tooling) — not API-assertable; supply a SAF attestation.'
 end
end
