control 'SV-257291' do
  title 'The container platform must enforce organization-defined circumstances and/or
                usage conditions for organization-defined accounts.'
  desc 'Activity under unusual conditions can indicate
                hostile activity. For example, what is normal activity during business hours can
                indicate hostile activity if it occurs during off hours. Depending on mission needs
                and conditions, account usage restrictions based on conditions and circumstances may
                be critical to limit access to resources and data to comply with operational or
                mission access control requirements. Thus, the application must be configured to
                enforce the specific conditions or circumstances under which application accounts
                can be used (e.g., by restricting usage to certain days of the week, time of day, or
                specific durations of
                time).'
  desc 'check', 'Determine if the container platform is configured to enforce
                    organization-defined circumstances and/or usage conditions for
                    organization-defined accounts. If the container platform does not enforce
                    organization-defined circumstances and/or usage conditions for
                    organization-defined accounts, this is a finding.'
  desc 'fix', 'Configure the container platform to enforce
                organization-defined circumstances and/or usage conditions for organization-defined
                accounts.'
  impact 0.5
  tag check_id: 'C-60975r919159_chk'
  tag severity: 'medium'
  tag gid: 'V-257291'
  tag rid: 'SV-257291r961287_rule'
  tag stig_id: 'SRG-APP-000318-CTR-000740'
  tag gtitle: 'SRG-APP-000318'
  tag fix_id: 'F-60902r919160_fix'
  tag 'documentable'
  tag cci: ['CCI-002145']
  tag nist: ['AC-2 (11)']
  tag implementation_status: 'inherited'
  tag inherited_from: 'aws-shared-responsibility'

  # AWS-managed: IAM identity internals / Fargate runtime / platform config (FedRAMP/DoD ATO).
  ev = input('inherited_evidence_uri', value: '')
  ev = attestation_uri(:leveraged, 'aws-container-platform-authorization', ext: 'json') if ev.to_s.empty?
  max_age = input('leveraged_evidence_max_age_days', value: 365)
  impact 0.5
  if ev.to_s.empty?
    describe 'AWS-inherited authorization evidence' do
      skip 'inherited-from-aws: AWS-managed layer; set leveraged_evidence_base/inherited_evidence_uri to the AWS FedRAMP/DoD authorization manifest, or supply a SAF attestation.'
    end
  else
    doc = document_attestation(ev, max_age_days: max_age)
    describe "AWS authorization evidence (#{ev})" do
      it('exists') { expect(doc.exists?).to eq(true) }
      it('current') { expect(doc.current?(max_age)).to eq(true) }
    end
  end
end
