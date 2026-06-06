control 'SV-233271' do
  title 'The container platform must use a valid FIPS 140-2 or FIPS 140-3 approved
                cryptographic module to generate hashes.'
  desc 'The cryptographic module used must have at least one
                validated hash algorithm. This validated hash algorithm must be used to generate
                cryptographic hashes for all cryptographic security function within the container
                platform components being evaluated. FIPS 140-2/140-3 precludes the use of
                invalidated cryptography for the cryptographic protection of sensitive or valuable
                data within federal systems. Unvalidated cryptography is viewed by NIST as providing
                no protection to the information or data. In effect, the data would be considered
                unprotected plaintext. If the agency specifies that the information or data be
                cryptographically protected, then FIPS 140-2/140-3 is applicable. In essence, if
                cryptography is required, it must be validated. Cryptographic modules that have been
                approved for classified use may be used in lieu of modules that have been validated
                against the FIPS 140-2/140-3 standard. This requirement also applies to Zero Trust
                initiatives.'
  desc 'check', 'Review the container platform configuration to validate that valid
                    FIPS 140-2/140-3 approved cryptographic modules are being used to generate
                    hashes. If non-valid or unapproved FIPS 140-2/140-3 cryptographic modules are
                    being used to generate hashes, this is a finding.'
  desc 'fix', 'Configure the container platform to use valid FIPS
                140-2/140-3 approved cryptographic modules to generate hashes.'
  impact 0.5
  tag check_id: 'C-36207r1137628_chk'
  tag severity: 'medium'
  tag gid: 'V-233271'
  tag rid: 'SV-233271r1137647_rule'
  tag stig_id: 'SRG-APP-000514-CTR-001315'
  tag gtitle: 'SRG-APP-000514'
  tag fix_id: 'F-36175r1137629_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
