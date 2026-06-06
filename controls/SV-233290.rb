control 'SV-233290' do
  title 'The container platform must prohibit or restrict the use of protocols that
                transmit unencrypted authentication information or use flawed cryptographic
                algorithms for transmission.'
  desc 'The use of secure ports, protocols and services
                within the container platform must be controlled and conform to the PPSM CAL. Those
                ports, protocols, and services that fall outside the PPSM CAL must be blocked by the
                runtime. Instructions on the PPSM can be found in organization Instruction 8551.01 Policy.
                Unsecure protocols for transmission will expose the information system data and
                information, making the session susceptible to manipulation, hijacking, and
                man-in-the middle
                attacks.'
  desc 'check', 'Review the container platform configuration to verify that container
                    platform is not using protocols that transmit authentication data unencrypted
                    and that the container platform is not using flawed cryptographic algorithms for
                    transmission. If the container platform is using protocols to transmit
                    authentication data unencrypted or is using flawed cryptographic algorithms,
                    this is a finding.'
  desc 'fix', 'Configure the container platform to use protocols
                that transmit authentication data encrypted and to use cryptographic algorithms that
                are not flawed.'
  impact 0.7
  tag check_id: 'C-36226r601859_chk'
  tag severity: 'high'
  tag gid: 'V-233290'
  tag rid: 'SV-233290r961911_rule'
  tag stig_id: 'SRG-APP-000645-CTR-001410'
  tag gtitle: 'SRG-APP-000645'
  tag fix_id: 'F-36194r601358_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
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
