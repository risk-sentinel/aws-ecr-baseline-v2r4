control 'SV-233087' do
  title 'The container platform must disable identifiers (individuals, groups, roles, and
                devices) after 35 days of inactivity.'
  desc 'Inactive identifiers pose a risk to systems and
                applications. Attackers that are able to exploit an inactive identifier can
                potentially obtain and maintain undetected access to the application. Owners of
                inactive accounts will not notice if unauthorized access to their user account has
                been obtained. Applications need to track periods of inactivity and disable
                application identifiers after 35 days of inactivity. Management of user identifiers
                is not applicable to shared information system accounts (e.g., guest and anonymous
                accounts). It is commonly the case that a user account is the name of an information
                system account associated with an individual. To avoid having to build complex user
                management capabilities directly into their application, wise developers leverage
                the underlying OS or other user account management infrastructure (AD, LDAP) that is
                already in place within the organization and meets organizational user account
                management
                requirements.'
  desc 'check', 'Review the container platform configuration to determine if the
                    container platform is configured to disable identifiers (individuals, groups,
                    roles, and devices) after 35 days of inactivity. If identifiers are not disabled
                    after 35 days of inactivity, this is a finding.'
  desc 'fix', 'Configure the container platform to disable
                identifiers (individuals, groups, roles, and devices) after 35 days of inactivity.'
  impact 0.5
  tag check_id: 'C-36023r601722_chk'
  tag severity: 'medium'
  tag gid: 'V-233087'
  tag rid: 'SV-233087r981853_rule'
  tag stig_id: 'SRG-APP-000163-CTR-000395'
  tag gtitle: 'SRG-APP-000163'
  tag fix_id: 'F-35991r600749_fix'
  tag 'documentable'
  tag cci: ['CCI-003627']
  tag nist: ['AC-2 (3) (a)']
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
