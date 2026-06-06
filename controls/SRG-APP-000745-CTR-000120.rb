control 'SRG-APP-000745-CTR-000120' do
  title 'The container platform must implement the capability to centrally review and
                analyze audit records from multiple components within the system.'
  desc 'Automated mechanisms for centralized reviews and
                analyses include Security Information and Event Management
                products.'
  desc 'check', 'Verify the container platform is configured to implement the
                    capability to centrally review and analyze audit records from multiple
                    components within the system. If the container platform is not configured to
                    implement the capability to centrally review and analyze audit records from
                    multiple components within the system, this is a finding.'
  desc 'fix', 'Configure the container platform to implement the
                capability to centrally review and analyze audit records from multiple components
                within the system.'
  impact 0.5
  tag check_id: 'C-67487r982454_chk'
  tag severity: 'medium'
  tag gid: 'V-263587'
  tag rid: 'SV-263587r982455_rule'
  tag stig_id: 'SRG-APP-000745-CTR-000120'
  tag gtitle: 'SRG-APP-000745'
  tag fix_id: 'F-67395r981900_fix'
  tag 'documentable'
  tag cci: ['CCI-003821']
  tag nist: ['AU-6 (4)']
end
