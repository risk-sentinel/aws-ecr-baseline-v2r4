control 'SV-233032' do
 title 'The container platform must display the organization-defined login banner before granting access to platform components.'
 desc 'The container platform has countless components where
 different access levels are needed. To control access, the user must first log in to
 the component and then be presented with a organization-approved use notification banner
 before granting access to the component. This guarantees privacy and security
 notification verbiage used is consistent with applicable federal laws, Executive
 Orders, directives, policies, regulations, standards, and
 guidance.'
 desc 'check', 'Review the container platform configuration to determine if the
 the organization-defined login banner is configured to be displayed
 before granting access to platform components. Log in to the container platform
 components and verify that the organization-defined login banner
 is being displayed before granting access. If the organization-defined login banner
 and Consent Banner is not configured or is not displayed before granting access
 to container platform components, this is a finding.'
 desc 'fix', 'Configure the container platform to display the
 the organization-defined login banner before granting access to container
 platform components.'
 impact 0.3
 tag check_id: 'C-35968r601608_chk'
 tag severity: 'low'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233032'
 tag rid: 'SV-233032r960843_rule'
 tag stig_id: 'SRG-APP-000068-CTR-000120'
 tag gtitle: 'SRG-APP-000068'
 tag fix_id: 'F-35936r600584_fix'
 tag 'documentable'
 tag cci: ['CCI-000048']
 tag nist: ['AC-8 a']
 tag implementation_status: 'not-applicable'

 impact 0.0
 describe 'the organization-defined login banner display: no platform-provided interactive session/console UI; AWS Console access is AWS-governed (N/A)' do
 subject { true }
 it { is_expected.to eq true }
 end
end
