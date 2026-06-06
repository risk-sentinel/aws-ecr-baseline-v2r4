control 'SV-263594' do
  title 'The container platform must for password-based authentication, verify when users
                create or update passwords, that the passwords are not found on the list of
                commonly-used, expected, or compromised passwords in IA-5 (1) (a).'
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
  desc 'check', 'Verify the container platform is configured to verify when users
                    create or update passwords, that the passwords are not found on the list of
                    commonly-used, expected, or compromised passwords in IA-5 (1) (a). If the
                    container platform is not configured to verify when users create or update
                    passwords, that the passwords are not found on the list of commonly-used,
                    expected, or compromised passwords in IA-5 (1) (a), this is a finding.'
  desc 'fix', 'Configure the container platform to verify when
                users create or update passwords, that the passwords are not found on the list of
                commonly-used, expected, or compromised passwords in IA-5 (1) (a).'
  impact 0.5
  tag check_id: 'C-67494r982462_chk'
  tag severity: 'medium'
  tag gid: 'V-263594'
  tag rid: 'SV-263594r982463_rule'
  tag stig_id: 'SRG-APP-000845-CTR-000220'
  tag gtitle: 'SRG-APP-000845'
  tag fix_id: 'F-67402r981921_fix'
  tag 'documentable'
  tag cci: ['CCI-004061']
  tag nist: ['IA-5 (1) (b)']
end
