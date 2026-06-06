control 'SV-233096' do
  title 'For accounts using password authentication, the container platform must use
                FIPS-validated SHA-2 or later protocol to protect the integrity of the password
                authentication process.'
  desc 'Passwords need to be protected on entry, in
                transmission, during authentication, and when stored. If compromised at any of these
                security points, a nefarious user can use the password along with stolen user
                account information to gain access or to escalate privileges. The container platform
                may require account authentication during container platform tasks and before
                accessing container platform components, e.g. runtime, registry, and keystore.
                During any user authentication, the container platform must use FIPS-validated SHA-2
                or later protocol to protect the integrity of the password authentication
                process.'
  desc 'check', 'Review the documentation and configuration to determine if the
                    container platform enforces the required FIPS-validated encrypt passwords when
                    they are transmitted. If the container platform is not configured to meet this
                    requirement, this is a finding.'
  desc 'fix', 'Configure the container platform to transmit only
                encrypted FIPS-validated SHA-2 or later representations of passwords.'
  impact 0.7
  tag check_id: 'C-36032r600775_chk'
  tag severity: 'high'
  tag gid: 'V-233096'
  tag rid: 'SV-233096r961029_rule'
  tag stig_id: 'SRG-APP-000172-CTR-000440'
  tag gtitle: 'SRG-APP-000172'
  tag fix_id: 'F-36000r600776_fix'
  tag 'documentable'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
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
