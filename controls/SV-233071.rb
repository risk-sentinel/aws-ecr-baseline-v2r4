control 'SV-233071' do
  title 'The container platform must be configured with only essential configurations.'
  desc 'The container platform can be built with components
                that are not used for the intended purpose of the organization. To limit the attack
                surface of the container platform, it is essential that the non-essential services
                are not
                installed.'
  desc 'check', 'Review the container platform configuration and verify that only
                    those components needed for operation are installed. If components are installed
                    that are not used for the intended purpose of the organization, this is a
                    finding.'
  desc 'fix', 'Identify the role the container platform is
                intended to play in the production environment and remove any components that are
                not needed or used for the intended purpose.'
  impact 0.5
  tag check_id: 'C-36007r600700_chk'
  tag severity: 'medium'
  tag gid: 'V-233071'
  tag rid: 'SV-233071r960963_rule'
  tag stig_id: 'SRG-APP-000141-CTR-000315'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-35975r600701_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
  tag implementation_status: 'inherited'
  tag inherited_from: 'aws-shared-responsibility'

  # AWS-managed: IAM identity internals / Fargate runtime / platform config (the cloud-provider authorization).
  ev = input('inherited_evidence_uri', value: '')
  ev = attestation_uri(:leveraged, 'aws-container-platform-authorization', ext: 'json') if ev.to_s.empty?
  max_age = input('leveraged_evidence_max_age_days', value: 365)
  impact 0.5
  if ev.to_s.empty?
    describe 'AWS-inherited authorization evidence' do
      skip 'inherited-from-aws: AWS-managed layer; set leveraged_evidence_base/inherited_evidence_uri to the cloud-provider authorization manifest, or supply a SAF attestation.'
    end
  else
    doc = document_attestation(ev, max_age_days: max_age)
    describe "AWS authorization evidence (#{ev})" do
      it('exists') { expect(doc.exists?).to eq(true) }
      it('current') { expect(doc.current?(max_age)).to eq(true) }
    end
  end
end
