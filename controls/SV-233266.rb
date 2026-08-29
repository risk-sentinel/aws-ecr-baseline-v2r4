control 'SV-233266' do
 title 'The container platform must generate audit records when concurrent logons from
 different workstations and systems occur.'
 desc 'The container platform and its components must
 generate audit records for concurrent logons from workstations perform remote
 maintenance, runtime instances, connectivity to the container registry, and
 keystore. All the components must use the same standard so the events can be tied
 together to understand what took place within the overall container platform. This
 must establish, correlate, and help assist with investigating the events relating to
 an incident, or identify those
 responsible.'
 desc 'check', 'Review the container platform configuration for audit logon events.
 Ensure audit policy for concurrent logons from different workstations and
 systems is enabled. Verify events are written to the log. Validate system
 documentation is current. If concurrent logons from different workstations and
 systems do not generate log records, this is a finding.'
 desc 'fix', 'Configure the container platform to generate audit
 log for concurrent logins from multiple workstations and systems. Revise all
 applicable system documentation.'
 impact 0.5
 tag check_id: 'C-36202r601841_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233266'
 tag rid: 'SV-233266r961833_rule'
 tag stig_id: 'SRG-APP-000506-CTR-001290'
 tag gtitle: 'SRG-APP-000506'
 tag fix_id: 'F-36170r601286_fix'
 tag 'documentable'
 tag cci: ['CCI-000172']
 tag nist: ['AU-12 c']
 tag implementation_status: 'implemented'

 # Durable, tamper-evident audit-record generation via account CloudTrail (cross-validates
 # cis-aws-foundations). CloudTrail's record schema carries event type/time/source/user.
 ok = audit_trail_compliant?
 impact 0.5
 describe 'CloudTrail audit-record generation (multi-region + log-file-validation + S3)' do
 subject { ok }
 it { is_expected.to be true }
 end
end
