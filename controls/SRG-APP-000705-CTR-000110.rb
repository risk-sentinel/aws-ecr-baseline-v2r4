control 'SRG-APP-000705-CTR-000110' do
  title 'The container platform must disable accounts when the accounts are no longer
                associated to a user.'
  desc 'Disabling expired, inactive, or otherwise anomalous
                accounts supports the concepts of least privilege and least functionality which
                reduce the attack surface of the
                system.'
  desc 'check', 'Verify the container platform is configured to disable accounts when
                    the accounts are no longer associated to a user. If the container platform is
                    not configured to disable accounts when the accounts are no longer associated to
                    a user, this is a finding.'
  desc 'fix', 'Configure the container platform to disable
                accounts when the accounts are no longer associated to a user.'
  impact 0.5
  tag check_id: 'C-67486r982452_chk'
  tag severity: 'medium'
  tag gid: 'V-263586'
  tag rid: 'SV-263586r982453_rule'
  tag stig_id: 'SRG-APP-000705-CTR-000110'
  tag gtitle: 'SRG-APP-000705'
  tag fix_id: 'F-67394r981897_fix'
  tag 'documentable'
  tag cci: ['CCI-003628']
  tag nist: ['AC-2 (3) (b)']
end
