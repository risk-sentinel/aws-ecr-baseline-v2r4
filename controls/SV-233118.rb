control 'SV-233118' do
  title 'The container platform must protect authenticity of communications sessions with
                the use of FIPS-validated 140-2 or 140-3 security requirements for cryptographic
                modules.'
  desc 'The container platform is responsible for pulling
                images from trusted sources and placing those images into its registry. To protect
                the transmission of images, the container platform must use FIPS-validated 140-2 or
                140-3 cryptographic modules. This added protection defends against
                main-in-the-middle attacks where malicious code could be added to an image during
                transmission.'
  desc 'check', 'Review the container platform configuration to determine if
                    FIPS-validated 140-2 or 140-3 cryptographic modules are being used to protect
                    container images during transmission. If FIPS-validated 140-2 or 140-3
                    cryptographic modules are not being use, this is a finding.'
  desc 'fix', 'Configure the container platform to use
                FIPS-validated 140-2 or 140-3 cryptographic modules to protect container images
                during transmission.'
  impact 0.7
  tag check_id: 'C-36054r601744_chk'
  tag severity: 'high'
  tag gid: 'V-233118'
  tag rid: 'SV-233118r1043178_rule'
  tag stig_id: 'SRG-APP-000219-CTR-000550'
  tag gtitle: 'SRG-APP-000219'
  tag fix_id: 'F-36022r600842_fix'
  tag 'documentable'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
  tag implementation_status: 'inherited'
  tag inherited_from: 'aws-shared-responsibility'

  # AWS-managed container-platform layer (runtime/host/control-plane/crypto-module/audit-
  # infra). Evidence = the leveraged AWS FedRAMP/DoD authorization manifest; Skip (not a
  # vacuous pass) until the consumer configures leveraged_evidence_base/inherited_evidence_uri.
  ev = input('inherited_evidence_uri', value: '')
  ev = attestation_uri(:leveraged, 'aws-container-platform-authorization', ext: 'json') if ev.to_s.empty?
  max_age = input('leveraged_evidence_max_age_days', value: 365)
  impact 0.5
  if ev.to_s.empty?
    describe 'AWS-inherited authorization evidence' do
      skip 'inherited-from-aws: AWS-managed layer; set leveraged_evidence_base / inherited_evidence_uri to the AWS FedRAMP/DoD authorization manifest, or supply a SAF attestation.'
    end
  else
    doc = document_attestation(ev, max_age_days: max_age)
    describe "AWS authorization evidence (#{ev})" do
      it('exists')  { expect(doc.exists?).to eq(true) }
      it('current') { expect(doc.current?(max_age)).to eq(true) }
    end
  end
end
