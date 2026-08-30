control 'SV-263596' do
 title 'The container platform must for password-based authentication, allow user
 selection of long passwords and passphrases, including spaces and all printable
 characters.'
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
 desc 'check', 'Verify the container platform is configured to allow user selection
 of long passwords and passphrases, including spaces and all printable
 characters. If the container platform is not configured to allow user selection
 of long passwords and passphrases, including spaces and all printable
 characters, this is a finding.'
 desc 'fix', 'Configure the container platform to allow user
 selection of long passwords and passphrases, including spaces and all printable
 characters.'
 impact 0.5
 tag check_id: 'C-67496r982466_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-263596'
 tag rid: 'SV-263596r982467_rule'
 tag stig_id: 'SRG-APP-000860-CTR-000250'
 tag gtitle: 'SRG-APP-000860'
 tag fix_id: 'F-67404r981927_fix'
 tag 'documentable'
 tag cci: ['CCI-004064']
 tag nist: ['IA-5 (1) (f)']
 tag nist_r4: ['IA-5 (1)']
 tag ksi:  ['KSI-IAM-APM']
 tag implementation_status: 'alternative'
 tag attestation_category: 'operational'

 impact 0.5
 describe 'operational/governance control (SAF attestation)' do
 skip 'organizational/operational control (alerting, governance policy, or password-breach tooling) — not API-assertable; supply a SAF attestation.'
 end
end
