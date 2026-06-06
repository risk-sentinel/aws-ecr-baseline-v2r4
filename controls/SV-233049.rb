control 'SV-233049' do
  title 'The container platform must generate audit records containing the full-text
                recording of privileged commands or the individual identities of group account
                users.'
  desc "During an investigation of an incident, it is
                important to fully understand what took place. Often, information is not part of the
                audited event due to the data's nature, security risk, or audit log size.
                Organizations must consider limiting the additional audit information to only that
                information explicitly needed for specific audit requirements. At a minimum, the
                organization must audit either full-text recording of privileged commands, or the
                individual identities of group users, or
                both."
  desc 'check', 'Review the documentation and deployment configuration to determine if
                    the container platform is configured to generate full-text recording of
                    privileged commands or the individual identities of group users at a minimum.
                    Have a user execute a privileged command and review the log data to validate
                    that the full-text or identity of the individual is being logged. If the
                    container platform is not meeting this requirement, this is a finding.'
  desc 'fix', 'Configure the container platform to generate the
                full-text recording of privileged commands, or the individual identities of group
                users, or both.'
  impact 0.5
  tag check_id: 'C-35985r601634_chk'
  tag severity: 'medium'
  tag gid: 'V-233049'
  tag rid: 'SV-233049r960909_rule'
  tag stig_id: 'SRG-APP-000101-CTR-000205'
  tag gtitle: 'SRG-APP-000101'
  tag fix_id: 'F-35953r600635_fix'
  tag 'documentable'
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)']
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
