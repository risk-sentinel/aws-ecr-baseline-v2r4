control 'SRG-APP-000880-CTR-000290' do
  title 'The container platform must protect nonlocal maintenance sessions by separating
                the maintenance session from other network sessions with the system by logically
                separated communications paths.'
  desc 'Nonlocal maintenance and diagnostic activities are
                conducted by individuals who communicate through either an external or internal
                network. Communications paths can be logically separated using
                encryption.'
  desc 'check', 'Verify the container platform is configured to protect nonlocal
                    maintenance sessions by separating the maintenance session from other network
                    sessions with the system by logically separated communications paths. If the
                    container platform is not configured to protect nonlocal maintenance sessions by
                    separating the maintenance session from other network sessions with the system
                    by logically separated communications paths, this is a finding.'
  desc 'fix', 'Configure the container platform to protect
                nonlocal maintenance sessions by separating the maintenance session from other
                network sessions with the system by logically separated communications paths.'
  impact 0.5
  tag check_id: 'C-67498r982470_chk'
  tag severity: 'medium'
  tag gid: 'V-263598'
  tag rid: 'SV-263598r982471_rule'
  tag stig_id: 'SRG-APP-000880-CTR-000290'
  tag gtitle: 'SRG-APP-000880'
  tag fix_id: 'F-67406r981933_fix'
  tag 'documentable'
  tag cci: ['CCI-004192']
  tag nist: ['MA-4 (4) (b) (2)']
end
