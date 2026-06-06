control 'SV-233258' do
  title 'The container platform must generate audit records when successful/unsuccessful
                attempts to modify categories of information (e.g., classification levels) occur.'
  desc 'Without generating audit records that are specific to
                the security and mission needs of the organization, it would be difficult to
                establish, correlate, and investigate the events relating to an incident, or
                identify those responsible for one. Audit records can be generated from various
                components within the information system (e.g., module or policy
                filter).'
  desc 'check', 'Review the container platform configuration to verify audit records
                    are generated when successful/unsuccessful attempts are made to modify
                    categories of information. If audit records are not generated, this is a
                    finding.'
  desc 'fix', 'Configure the container platform to generate audit
                records when successful/unsuccessful attempts are made to modify categories of
                information.'
  impact 0.5
  tag check_id: 'C-36194r601261_chk'
  tag severity: 'medium'
  tag gid: 'V-233258'
  tag rid: 'SV-233258r961809_rule'
  tag stig_id: 'SRG-APP-000498-CTR-001250'
  tag gtitle: 'SRG-APP-000498'
  tag fix_id: 'F-36162r601262_fix'
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
