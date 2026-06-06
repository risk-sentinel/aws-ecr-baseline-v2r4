control 'SV-233202' do
  title 'The container platform must accept a hardware authenticator (e.g., smartcard)
                credentials from other federal agencies.'
  desc 'Controlling access to the container platform and its
                components is paramount in having a secure and stable system. Validating users is
                the first step in controlling the access. Users may be validated by the overall
                container platform or they may be validated by each component. It is essential to
                accept hardware-authenticator credentials from other federal agencies and eliminate the possibility of
                access being denied to authorized users. hardware-authenticator credentials are those credentials
                issued by federal agencies that conform to FIPS Publication 201 and supporting
                guidance documents. OMB Memorandum 11-11 requires federal agencies to continue
                implementing the requirements specified in HSPD-12 to enable agency-wide use of hardware authenticator
                credentials.'
  desc 'check', 'Review the documentation and configuration to determine if the
                    container platform accepts hardware-authenticator credentials from other federal agencies. If the
                    container platform does not accept other federal agency hardware-authenticator credentials, this is
                    a finding.'
  desc 'fix', 'Configure the container platform to accept hardware authenticator
                credentials from other federal agencies.'
  impact 0.5
  tag check_id: 'C-36138r601093_chk'
  tag severity: 'medium'
  tag gid: 'V-233202'
  tag rid: 'SV-233202r961527_rule'
  tag stig_id: 'SRG-APP-000402-CTR-000970'
  tag gtitle: 'SRG-APP-000402'
  tag fix_id: 'F-36106r601094_fix'
  tag 'documentable'
  tag cci: ['CCI-002009']
  tag nist: ['IA-8 (1)']
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
