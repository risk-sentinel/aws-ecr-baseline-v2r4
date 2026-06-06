control 'SV-233129' do
  title "The container platform must restrict individuals' ability to launch
                organizationally defined denial-of-service (DoS) attacks against other information
                systems."
  desc 'The container platform will offer services to users
                and these services share resources available on the hosting system. To share the
                resources in a manner that does not exhaust or over utilize resources, it is
                necessary for the container platform to have mechanisms that allow developers to
                size there containers to provide minimum and maximum amounts. If there is no
                mechanism to specify limits, container services can cause DoS by over
                utilization.'
  desc 'check', 'Review the container platform implementation and security
                    documentation and components settings to determine if the information system
                    restricts the ability of users or systems to launch organization-defined DoS
                    attacks against other information systems or networks from the container
                    platform. If the container platform is not configured to restrict this ability,
                    this is a finding.'
  desc 'fix', 'Configure the container platform to restrict the
                ability of users or other systems to launch DoS attacks from the container platform
                components by setting resource quotas on resources such as memory, storage, and CPU
                utilization.'
  impact 0.5
  tag check_id: 'C-36065r601756_chk'
  tag severity: 'medium'
  tag gid: 'V-233129'
  tag rid: 'SV-233129r961152_rule'
  tag stig_id: 'SRG-APP-000246-CTR-000605'
  tag gtitle: 'SRG-APP-000246'
  tag fix_id: 'F-36033r600875_fix'
  tag 'documentable'
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
  tag implementation_status: 'alternative'
  tag attestation_category: 'governance'

  impact 0.5
  describe 'Organization-defined restriction on who may launch is governance policy' do
    skip 'Organization-defined restriction on who may launch is governance policy — organizational/governance control, not API-assertable; supply a SAF attestation (inspec-reporter-json-hdf.attestations).'
  end
end
