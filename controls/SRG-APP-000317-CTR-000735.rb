control 'SRG-APP-000317-CTR-000735' do
  title 'The container platform must terminate shared/group account credentials when
                members leave the group.'
  desc 'If shared/group account credentials are not
                terminated when individuals leave the group, the user that left the group can still
                gain access even though they are no longer authorized. A shared/group account
                credential is a shared form of authentication that allows multiple individuals to
                access the application using a single account. There may also be instances when
                specific user actions need to be performed on the information system without unique
                user identification or authentication. Examples of credentials include passwords and
                group membership
                certificates.'
  desc 'check', 'Determine if the container platform is configured to terminate
                    shared/group account credentials when members leave the group. If the container
                    platform does not terminated shared/group account credentials when members leave
                    the group, this is a finding.'
  desc 'fix', 'Configure the container platform to terminate
                shared/group account credentials when members leave the group.'
  impact 0.5
  tag check_id: 'C-36091r600952_chk'
  tag severity: 'medium'
  tag gid: 'V-233155'
  tag rid: 'SV-233155r981875_rule'
  tag stig_id: 'SRG-APP-000317-CTR-000735'
  tag gtitle: 'SRG-APP-000317'
  tag fix_id: 'F-36059r600953_fix'
  tag 'documentable'
  tag cci: ['CCI-004045']
  tag nist: ['IA-2 (5)']
end
