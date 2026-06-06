control 'SV-233211' do
  title 'The container platform must implement approved cryptography to protect
                classified information in accordance with applicable federal laws, Executive Orders,
                directives, policies, regulations, and standards.'
  desc 'Use of weak or untested encryption algorithms
                undermines the purposes of utilizing encryption to protect data and images. The
                container platform must implement cryptographic modules adhering to the higher
                standards approved by the federal government since this provides assurance they have
                been tested and
                validated.'
  desc 'check', 'Review documentation to verify that the container platform is using
                    approved cryptography to protect classified data and applications. If the
                    container platform is not using approved cryptography for classified data
                    and applications, this is a finding.'
  desc 'fix', 'Configure the container platform to utilize
                approved cryptography to protect classified information.'
  impact 0.5
  tag check_id: 'C-36147r601811_chk'
  tag severity: 'medium'
  tag gid: 'V-233211'
  tag rid: 'SV-233211r961863_rule'
  tag stig_id: 'SRG-APP-000416-CTR-001015'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-36115r601121_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
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
