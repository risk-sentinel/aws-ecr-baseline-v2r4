control 'SV-233262' do
 title 'The container platform must generate audit records when successful/unsuccessful
 attempts to delete categories of information (e.g., classification levels) occur.'
 desc 'Without generating audit records that are specific to
 the security and mission needs of the organization, it would be difficult to
 establish, correlate, and investigate the events relating to an incident, or
 identify those responsible for one. Audit records can be generated from various
 components within the information system (e.g., module or policy
 filter).'
 desc 'check', 'Review the container platform configuration to determine if audit
 records are generated on successful/unsuccessful attempts to delete categories
 of information occur. If audit records are not generated, this is a finding.'
 desc 'fix', 'Configure the container platform to generate audit
 records on successful/unsuccessful attempts to delete categories of information
 occur.'
 impact 0.5
 tag check_id: 'C-36198r601273_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233262'
 tag rid: 'SV-233262r961821_rule'
 tag stig_id: 'SRG-APP-000502-CTR-001270'
 tag gtitle: 'SRG-APP-000502'
 tag fix_id: 'F-36166r601274_fix'
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
