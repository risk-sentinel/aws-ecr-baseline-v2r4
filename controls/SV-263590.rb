control 'SV-263590' do
 title 'The container platform must implement multifactor authentication for local;
 network; and/or remote access to privileged accounts; and/or nonprivileged accounts
 such that the device meets organization-defined strength of mechanism requirements.'
 desc 'The purpose of requiring a device that is separate
 from the system to which the user is attempting to gain access for one of the
 factors during multifactor authentication is to reduce the likelihood of
 compromising authenticators or credentials stored on the system. Adversaries may be
 able to compromise such authenticators or credentials and subsequently impersonate
 authorized users. Implementing one of the factors on a separate device (e.g., a
 hardware token), provides a greater strength of mechanism and an increased level of
 assurance in the authentication
 process.'
 desc 'check', 'Verify the container platform is configured to implement multifactor
 authentication for local; network; and/or remote access to privileged accounts;
 and/or nonprivileged accounts such that the device meets organization-defined
 strength of mechanism requirements. If the container platform is not configured
 to implement multifactor authentication for local; network; and/or remote access
 to privileged accounts; and/or nonprivileged accounts such that the device meets
 organization-defined strength of mechanism requirements, this is a finding.'
 desc 'fix', 'Configure the container platform to implement
 multi-factor authentication for local; network; and/or remote access to privileged
 accounts; and/or nonprivileged accounts such that the device meets
 organization-defined strength of mechanism requirements.'
 impact 0.5
 tag check_id: 'C-67490r981908_chk'
 tag severity: 'medium'
 tag gid: 'V-263590'
 tag rid: 'SV-263590r981910_rule'
 tag stig_id: 'SRG-APP-000825-CTR-000180'
 tag gtitle: 'SRG-APP-000825'
 tag fix_id: 'F-67398r981909_fix'
 tag 'documentable'
 tag cci: ['CCI-004047']
 tag nist: ['IA-2 (6) (b)']
 tag implementation_status: 'implemented'

 # MFA: AWS IAM root account MFA (the readily-assertable signal; per-user MFA needs the
 # credential report — not exposed by inspec-aws). Consumer MFA hygiene = cis-aws-foundations.
 impact 0.5
 describe aws_iam_root_user do
 it { should have_mfa_enabled }
 end
end
