control 'SV-263587' do
  title 'The container platform must implement the capability to centrally review and
                analyze audit records from multiple components within the system.'
  desc 'Automated mechanisms for centralized reviews and
                analyses include Security Information and Event Management
                products.'
  desc 'check', 'Verify the container platform is configured to implement the
                    capability to centrally review and analyze audit records from multiple
                    components within the system. If the container platform is not configured to
                    implement the capability to centrally review and analyze audit records from
                    multiple components within the system, this is a finding.'
  desc 'fix', 'Configure the container platform to implement the
                capability to centrally review and analyze audit records from multiple components
                within the system.'
  impact 0.5
  tag check_id: 'C-67487r982454_chk'
  tag severity: 'medium'
  tag gid: 'V-263587'
  tag rid: 'SV-263587r982455_rule'
  tag stig_id: 'SRG-APP-000745-CTR-000120'
  tag gtitle: 'SRG-APP-000745'
  tag fix_id: 'F-67395r981900_fix'
  tag 'documentable'
  tag cci: ['CCI-003821']
  tag nist: ['AU-6 (4)']
  tag implementation_status: 'inherited'
  tag inherited_from: 'aws-shared-responsibility'

  # AWS-managed container-platform layer (runtime/host/control-plane/crypto-module/audit-
  # infra). Evidence = the leveraged the cloud-provider authorization manifest; Skip (not a
  # vacuous pass) until the consumer configures leveraged_evidence_base/inherited_evidence_uri.
  ev = input('inherited_evidence_uri', value: '')
  ev = attestation_uri(:leveraged, 'aws-container-platform-authorization', ext: 'json') if ev.to_s.empty?
  max_age = input('leveraged_evidence_max_age_days', value: 365)
  impact 0.5
  if ev.to_s.empty?
    describe 'AWS-inherited authorization evidence' do
      skip 'inherited-from-aws: AWS-managed layer; set leveraged_evidence_base / inherited_evidence_uri to the cloud-provider authorization manifest, or supply a SAF attestation.'
    end
  else
    doc = document_attestation(ev, max_age_days: max_age)
    describe "AWS authorization evidence (#{ev})" do
      it('exists')  { expect(doc.exists?).to eq(true) }
      it('current') { expect(doc.current?(max_age)).to eq(true) }
    end
  end
end
