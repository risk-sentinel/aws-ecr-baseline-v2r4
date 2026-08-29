control 'SV-233259' do
 title 'The container platform must generate audit records when successful/unsuccessful
 attempts to delete privileges occur.'
 desc 'Without generating audit records that are specific to
 the security and mission needs of the organization, it would be difficult to
 establish, correlate, and investigate the events relating to an incident, or
 identify those responsible for one. Audit records can be generated from various
 components within the information system (e.g., module or policy
 filter).'
 desc 'check', 'Review the container platform configuration to verify audit records
 are generated when successful/unsuccessful attempts are made to delete
 privileges. If audit records are not generated, this is a finding.'
 desc 'fix', 'Configure the container platform to generate audit
 records when successful/unsuccessful attempts are made to delete privileges occur.'
 impact 0.5
 tag check_id: 'C-36195r601264_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233259'
 tag rid: 'SV-233259r961812_rule'
 tag stig_id: 'SRG-APP-000499-CTR-001255'
 tag gtitle: 'SRG-APP-000499'
 tag fix_id: 'F-36163r601265_fix'
 tag 'documentable'
 tag cci: ['CCI-000172']
 tag nist: ['AU-12 c']
 tag ksi:  ['KSI-MLA-LET']
 tag nist_r4: ['AU-12 c']
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
