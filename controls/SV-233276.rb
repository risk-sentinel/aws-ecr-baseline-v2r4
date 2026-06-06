control 'SV-233276' do
  title 'The container platform must prohibit communication using TLS versions 1.0 and
                1.1, and SSL 2.0 and 3.0.'
  desc 'The container platform and its components will
                prohibit the use of SSL and unauthorized versions of TLS protocols to properly
                secure communication. The use of unsupported protocol exposes vulnerabilities to the
                container platform by rogue traffic interceptions, man-in-the middle-attacks, and
                impersonation of users or services from the container platform runtime, registry,
                and keystore. The container platform and its components will adhere to NIST
                800-52R2.'
  desc 'check', 'Review the container platform configuration to determine if TLS
                    versions 1.0 and 1.1, SSL 2.0 and 3.0 are prohibited for communication. If
                    communication using TLS versions 1.0 and 1.1, SSL 2.0 and 3.0 is permitted, this
                    is a finding.'
  desc 'fix', 'Configure the container platform to prohibit
                communication using TLS versions 1.0 and 1.1, SSL 2.0 and 3.0.'
  impact 0.5
  tag check_id: 'C-36212r601315_chk'
  tag severity: 'medium'
  tag gid: 'V-233276'
  tag rid: 'SV-233276r961869_rule'
  tag stig_id: 'SRG-APP-000560-CTR-001340'
  tag gtitle: 'SRG-APP-000560'
  tag fix_id: 'F-36180r601316_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
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
