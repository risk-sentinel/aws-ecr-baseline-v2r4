control 'SV-263592' do
 title 'The container platform must for password-based authentication, update the list of
 passwords on an organization-defined frequency.'
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
 passwords on an organization-defined frequency. If the container platform is not
 configured to update the list of passwords on an organization-defined frequency,
 this is a finding.'
 desc 'fix', 'Configure the container platform to update the list
 of passwords on an organization-defined frequency.'
 impact 0.5
 tag check_id: 'C-67492r982458_chk'
 tag severity: 'medium'
 tag gid: 'V-263592'
 tag rid: 'SV-263592r982459_rule'
 tag stig_id: 'SRG-APP-000835-CTR-000200'
 tag gtitle: 'SRG-APP-000835'
 tag fix_id: 'F-67400r981915_fix'
 tag 'documentable'
 tag cci: ['CCI-004059']
 tag nist: ['IA-5 (1) (a)']
 tag implementation_status: 'alternative'
 tag attestation_category: 'operational'

 impact 0.5
 describe 'operational/governance control (SAF attestation)' do
 skip 'organizational/operational control (alerting, governance policy, or password-breach tooling) — not API-assertable; supply a SAF attestation.'
 end
end
