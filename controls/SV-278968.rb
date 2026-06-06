control 'SV-278968' do
  title 'The container platform must be a version supported by the vendor.'
  desc 'Unsupported software and systems should not be used
                because fixes to newly identified bugs will not be implemented by the vendor. The
                lack of support can result in potential vulnerabilities. Software and systems at
                unsupported servicing levels or releases will not receive security updates for new
                vulnerabilities, which leaves them subject to exploitation. When maintenance updates
                and patches are no longer available, software is no longer considered supported and
                should be upgraded or
                decommissioned.'
  desc 'check', 'Verify the container platform is a version supported by the vendor.
                    If the container platform is not a version supported by the vendor, this is a
                    finding.'
  desc 'fix', 'Install a container platform version supported by
                the vendor.'
  impact 0.7
  tag check_id: 'C-83516r1137651_chk'
  tag severity: 'high'
  tag gid: 'V-278968'
  tag rid: 'SV-278968r1137653_rule'
  tag stig_id: 'SRG-APP-001035-CTR-000323'
  tag gtitle: 'SRG-APP-001035'
  tag fix_id: 'F-83421r1137652_fix'
  tag 'documentable'
  tag cci: ['CCI-003376']
  tag nist: ['SA-22 a']
end
