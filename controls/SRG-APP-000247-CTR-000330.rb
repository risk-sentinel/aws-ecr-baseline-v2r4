control 'SRG-APP-000247-CTR-000330' do
  title 'The container must have resource request limits set.'
  desc 'Setting a container resource request limit allows the
                container platform to determine the best location for the container to execute. The
                container platform looks at the resources available and finds the location that will
                require the minimum resources for the container to execute. Examples of resources
                that can be specified are CPU, memory, and
                storage.'
  desc 'check', 'Review the container platform configuration to determine that
                    resource limits are set. If the container platform does not enforce resource
                    limits, this is a finding.'
  desc 'fix', 'Configure the container platform to restrict the
                ability of users or other systems to launch denial-of-service (DoS) attacks from the
                container platform components by setting resource limits on resources such as
                memory, storage, and CPU utilization.'
  impact 0.5
  tag check_id: 'C-74910r1050644_chk'
  tag severity: 'medium'
  tag gid: 'V-270875'
  tag rid: 'SV-270875r1050646_rule'
  tag stig_id: 'SRG-APP-000247-CTR-000330'
  tag gtitle: 'SRG-APP-000247'
  tag fix_id: 'F-74811r1050645_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
