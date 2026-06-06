control 'SV-233016' do
  title 'The container platform must use TLS 1.2 or greater for secure communication.'
  desc 'The authenticity and integrity of the container
                platform and communication between nodes and components must be secure. If an
                insecure protocol is used during transmission of data, the data can be intercepted
                and manipulated. The manipulation of data can be used to inject status changes of
                the container platform, causing the execution of containers or reporting an
                incorrect healthcheck. To thwart the manipulation of the data during transmission, a
                secure protocol (TLS 1.2 or newer) must be used. Further guidance on secure
                transport protocols can be found in NIST SP
                800-52.'
  desc 'check', 'Review the container platform configuration to verify that TLS 1.2 or
                    greater is being used for communication by the container platform nodes and
                    components. If TLS 1.2 or greater is not being used for secure communication,
                    this is a finding.'
  desc 'fix', 'Configure the container platform to use TLS 1.2 or
                greater for node and component communication.'
  impact 0.5
  tag check_id: 'C-35952r600535_chk'
  tag severity: 'medium'
  tag gid: 'V-233016'
  tag rid: 'SV-233016r960759_rule'
  tag stig_id: 'SRG-APP-000014-CTR-000040'
  tag gtitle: 'SRG-APP-000014'
  tag fix_id: 'F-35920r600536_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
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
