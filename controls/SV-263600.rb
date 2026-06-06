control 'SV-263600' do
  title 'The container platform must provide protected storage for cryptographic keys with
                organization-defined safeguards and/or hardware protected key store.'
  desc 'A Trusted Platform Module (TPM) is an example of a
                hardware-protected data store that can be used to protect cryptographic
                keys.'
  desc 'check', 'Verify the container platform is configured to provide protected
                    storage for cryptographic keys with organization-defined safeguards and/or
                    hardware protected key store. If the container platform is not configured to
                    provide protected storage for cryptographic keys with organization-defined
                    safeguards and/or hardware protected key store, this is a finding.'
  desc 'fix', 'Configure the container platform to provide
                protected storage for cryptographic keys with organization-defined safeguards and/or
                hardware protected key store.'
  impact 0.5
  tag check_id: 'C-67500r982474_chk'
  tag severity: 'medium'
  tag gid: 'V-263600'
  tag rid: 'SV-263600r982475_rule'
  tag stig_id: 'SRG-APP-000915-CTR-000310'
  tag gtitle: 'SRG-APP-000915'
  tag fix_id: 'F-67408r981939_fix'
  tag 'documentable'
  tag cci: ['CCI-004910']
  tag nist: ['SC-28 (3)']
end
