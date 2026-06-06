control 'SV-233170' do
  title 'The container platform must provide an immediate warning to the SA and security officer (at a
                minimum) when allocated audit record storage volume reaches 75 percent of repository
                maximum audit record storage capacity.'
  desc 'If security personnel are not notified immediately
                upon storage volume utilization reaching 75 percent, they are unable to plan for
                storage capacity
                expansion.'
  desc 'check', 'Review the container platform configuration to determine if it is
                    configured to provide an immediate warning to the SA and security officer (at a minimum)
                    when allocated audit record storage volume reaches 75 percent of repository
                    maximum audit record storage capacity. If the container platform is not
                    configured to provide an immediate real-time alert, this is a finding.'
  desc 'fix', 'Configure the container platform to provide an
                immediate real-time alert to the SA and security officer when allocated audit record storage
                volume reaches 75 percent of repository maximum audit record storage capacity.'
  impact 0.5
  tag check_id: 'C-36106r601785_chk'
  tag severity: 'medium'
  tag gid: 'V-233170'
  tag rid: 'SV-233170r961398_rule'
  tag stig_id: 'SRG-APP-000359-CTR-000810'
  tag gtitle: 'SRG-APP-000359'
  tag fix_id: 'F-36074r600998_fix'
  tag 'documentable'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
  tag implementation_status: 'alternative'
  tag attestation_category: 'operational'

  impact 0.5
  describe 'operational/governance control (SAF attestation)' do
    skip 'organizational/operational control (alerting, governance policy, or password-breach tooling) — not API-assertable; supply a SAF attestation.'
  end
end
