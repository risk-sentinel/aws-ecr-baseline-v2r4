control 'SV-233164' do
 title 'The container platform must audit the execution of privileged functions.'
 desc 'Privileged functions within the container platform
 can be component specific or can envelope the entire container platform. Because of
 the nature of the commands, it is important to understand what command was executed
 for either investigation of an incident or for debugging/error correction;
 therefore, privileged function execution must be
 audited.'
 desc 'check', 'Review container platform documentation and log configuration to
 verify the application server logs privileged activity. If the container
 platform is not configured to log privileged activity, this is a finding.'
 desc 'fix', 'Configure the container platform to log privileged
 activity.'
 impact 0.5
 tag check_id: 'C-36100r600979_chk'
 tag severity: 'medium'
 tag gid: 'V-233164'
 tag rid: 'SV-233164r961362_rule'
 tag stig_id: 'SRG-APP-000343-CTR-000780'
 tag gtitle: 'SRG-APP-000343'
 tag fix_id: 'F-36068r600980_fix'
 tag 'documentable'
 tag cci: ['CCI-002234']
 tag nist: ['AC-6 (9)']
 tag implementation_status: 'implemented'

 ok = audit_trail_compliant?
 impact 0.5
 describe 'CloudTrail audit-record generation (multi-region + log-file-validation + S3)' do
 subject { ok }
 it { is_expected.to be true }
 end
end
